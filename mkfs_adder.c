#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#define BS 4096u
#define INODE_SIZE 128u
#define ROOT_INO 1u
#define DIRECT_MAX 12

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t block_size;
    uint64_t total_blocks;
    uint64_t inode_count;
    uint64_t inode_bitmap_start;
    uint64_t inode_bitmap_blocks;
    uint64_t data_bitmap_start;
    uint64_t data_bitmap_blocks;
    uint64_t inode_table_start;
    uint64_t inode_table_blocks;
    uint64_t data_region_start;
    uint64_t data_region_blocks;
    uint64_t root_inode;
    uint64_t mtime_epoch;
    uint32_t flags;
    uint32_t checksum;
} superblock_t;
#pragma pack(pop)
_Static_assert(sizeof(superblock_t) == 116, "superblock must fit in one block");

#pragma pack(push,1)
typedef struct {
    uint16_t mode;
    uint16_t links;
    uint32_t uid;
    uint32_t gid;
    uint64_t size_bytes;
    uint64_t atime;
    uint64_t mtime;
    uint64_t ctime;
    uint32_t direct[DIRECT_MAX];
    uint32_t reserved_0;
    uint32_t reserved_1;
    uint32_t reserved_2;
    uint32_t proj_id;
    uint32_t uid16_gid16;
    uint64_t xattr_ptr;
    uint64_t inode_crc;
} inode_t;
#pragma pack(pop)
_Static_assert(sizeof(inode_t)==INODE_SIZE, "inode size mismatch");

#pragma pack(push,1)
typedef struct {
    uint32_t inode_no;
    uint8_t type;
    char name[58];
    uint8_t checksum;
} dirent64_t;
#pragma pack(pop)
_Static_assert(sizeof(dirent64_t)==64, "dirent size mismatch");

// ==========================DO NOT CHANGE THIS PORTION=========================
// These functions are there for your help. You should refer to the specifications to see how you can use them.
// ====================================CRC32====================================
uint32_t CRC32_TAB[256];
void crc32_init(void){
    for (uint32_t i=0;i<256;i++){
        uint32_t c=i;
        for(int j=0;j<8;j++) c = (c&1)?(0xEDB88320u^(c>>1)):(c>>1);
        CRC32_TAB[i]=c;
    }
}
uint32_t crc32(const void* data, size_t n){
    const uint8_t* p=(const uint8_t*)data; uint32_t c=0xFFFFFFFFu;
    for(size_t i=0;i<n;i++) c = CRC32_TAB[(c^p[i])&0xFF] ^ (c>>8);
    return c ^ 0xFFFFFFFFu;
}
// ====================================CRC32====================================

// WARNING: CALL THIS ONLY AFTER ALL OTHER SUPERBLOCK ELEMENTS HAVE BEEN FINALIZED
static uint32_t superblock_crc_finalize(superblock_t *sb) {
    sb->checksum = 0;
    uint32_t s = crc32((void *) sb, BS - 4);
    sb->checksum = s;
    return s;
}

void inode_crc_finalize(inode_t* ino){
    uint8_t tmp[INODE_SIZE];
    memcpy(tmp, ino, INODE_SIZE);
    memset(&tmp[120], 0, 8);
    uint32_t c = crc32(tmp, 120);
    ino->inode_crc = (uint64_t)c;
}

void dirent_checksum_finalize(dirent64_t* de) {
    const uint8_t* p = (const uint8_t*)de;
    uint8_t x = 0;
    for (int i = 0; i < 63; i++) x ^= p[i];
    de->checksum = x;
}

// CLI parsing structure
typedef struct {
    char *input_name;
    char *output_name;
    char *file_name;
} cli_args_t;

// Function to parse command line arguments
int parse_args(int argc, char *argv[], cli_args_t *args) {
    if (argc != 7) {
        fprintf(stderr, "Usage: %s --input <file> --output <file> --file <file>\n", argv[0]);
        return -1;
    }
    
    args->input_name = NULL;
    args->output_name = NULL;
    args->file_name = NULL;
    
    for (int i = 1; i < argc; i += 2) {
        if (strcmp(argv[i], "--input") == 0) {
            args->input_name = argv[i + 1];
        } else if (strcmp(argv[i], "--output") == 0) {
            args->output_name = argv[i + 1];
        } else if (strcmp(argv[i], "--file") == 0) {
            args->file_name = argv[i + 1];
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            return -1;
        }
    }
    
    // Validate arguments
    if (!args->input_name || !args->output_name || !args->file_name) {
        fprintf(stderr, "Error: All arguments are required\n");
        return -1;
    }
    return 0;
}

// Function to check if a bit is set in bitmap
int is_bit_set(uint8_t *bitmap, uint64_t bit_num) {
    uint64_t byte_num = bit_num / 8;
    uint8_t bit_offset = bit_num % 8;
    return (bitmap[byte_num] & (1 << bit_offset)) != 0;
}

// Function to set a bit in bitmap
void set_bit(uint8_t *bitmap, uint64_t bit_num) {
    uint64_t byte_num = bit_num / 8;
    uint8_t bit_offset = bit_num % 8;
    bitmap[byte_num] |= (1 << bit_offset);
}

uint64_t find_free_inode(uint8_t *inode_bitmap, uint64_t inode_count) {
    for (uint64_t i = 1; i < inode_count; i++) {
        if (!is_bit_set(inode_bitmap, i)) {
            return i + 1;
        }
    }
    return 0;
}

uint64_t find_free_data_block(uint8_t *data_bitmap, uint64_t data_region_blocks) {
    for (uint64_t i = 0; i < data_region_blocks; i++) {
        if (!is_bit_set(data_bitmap, i)) {
            return i;
        }
    }
    return UINT64_MAX;
}

// Function to add file to filesystem
int add_file_to_filesystem(const char *input_name, const char *output_name, const char *file_name) {
    // First, check if the file exists
    FILE *file_fp = fopen(file_name, "rb");
    if (!file_fp) {
        fprintf(stderr, "Error: Cannot open file %s\n", file_name);
        return -1;
    }
    
    // Get file size
    fseek(file_fp, 0, SEEK_END);
    long file_size = ftell(file_fp);
    fseek(file_fp, 0, SEEK_SET);
    
    if (file_size < 0) {
        fprintf(stderr, "Error: Cannot determine file size\n");
        fclose(file_fp);
        return -1;
    }
    
    if (file_size > DIRECT_MAX * BS) {
        fprintf(stderr, "Error: File too large to fit in 12 direct blocks\n");
        fclose(file_fp);
        return -1;
    }
    
    // Open input filesystem image
    FILE *input_fp = fopen(input_name, "rb");
    if (!input_fp) {
        fprintf(stderr, "Error: Cannot open input image %s\n", input_name);
        fclose(file_fp);
        return -1;
    }
    
    // Read superblock
    superblock_t sb;
    fread(&sb, sizeof(sb), 1, input_fp);
    
    // Validate magic number
    if (sb.magic != 0x4D565346) {
        fprintf(stderr, "Error: Invalid filesystem magic number\n");
        fclose(file_fp);
        fclose(input_fp);
        return -1;
    }
    
    // Read inode bitmap
    fseek(input_fp, sb.inode_bitmap_start * BS, SEEK_SET);
    uint8_t inode_bitmap[BS];
    fread(inode_bitmap, 1, BS, input_fp);
    
    // Read data bitmap
    fseek(input_fp, sb.data_bitmap_start * BS, SEEK_SET);
    uint8_t data_bitmap[BS];
    fread(data_bitmap, 1, BS, input_fp);
    
    // Find free inode
    uint64_t new_inode_num = find_free_inode(inode_bitmap, sb.inode_count);
    if (new_inode_num == 0) {
        fprintf(stderr, "Error: No free inodes available\n");
        fclose(file_fp);
        fclose(input_fp);
        return -1;
    }
    
    // Calculate blocks needed for the file
    uint64_t blocks_needed = (file_size + BS - 1) / BS;
    if (blocks_needed > DIRECT_MAX) {
        fprintf(stderr, "Error: File requires too many blocks\n");
        fclose(file_fp);
        fclose(input_fp);
        return -1;
    }
    
    // Find free data blocks
    uint64_t data_blocks[DIRECT_MAX] = {0};
    uint64_t blocks_found = 0;
    for (uint64_t i = 0; i < sb.data_region_blocks && blocks_found < blocks_needed; i++) {
        if (!is_bit_set(data_bitmap, i)) {
            data_blocks[blocks_found] = i;
            blocks_found++;
        }
    }
    
    if (blocks_found < blocks_needed) {
        fprintf(stderr, "Error: Not enough free data blocks\n");
        fclose(file_fp);
        fclose(input_fp);
        return -1;
    }
    
    // Copy input to output
    FILE *output_fp = fopen(output_name, "wb");
    if (!output_fp) {
        fprintf(stderr, "Error: Cannot create output image %s\n", output_name);
        fclose(file_fp);
        fclose(input_fp);
        return -1;
    }
    
    // Copy the entire input file to output
    fseek(input_fp, 0, SEEK_SET);
    uint8_t buffer[BS];
    for (uint64_t i = 0; i < sb.total_blocks; i++) {
        fread(buffer, 1, BS, input_fp);
        fwrite(buffer, 1, BS, output_fp);
    }
    
    fclose(input_fp);
    
    // Update inode bitmap
    set_bit(inode_bitmap, new_inode_num - 1); // Convert to 0-indexed for bitmap
    fseek(output_fp, sb.inode_bitmap_start * BS, SEEK_SET);
    fwrite(inode_bitmap, 1, BS, output_fp);
    
    // Update data bitmap
    for (uint64_t i = 0; i < blocks_needed; i++) {
        set_bit(data_bitmap, data_blocks[i]);
    }
    fseek(output_fp, sb.data_bitmap_start * BS, SEEK_SET);
    fwrite(data_bitmap, 1, BS, output_fp);
    
    // Create new inode for the file
    time_t now = time(NULL);
    inode_t new_inode = {0};
    new_inode.mode = 0100000;
    new_inode.links = 1;
    new_inode.uid = 0;
    new_inode.gid = 0;
    new_inode.size_bytes = file_size;
    new_inode.atime = now;
    new_inode.mtime = now;
    new_inode.ctime = now;
    
    // Set direct pointers
    for (uint64_t i = 0; i < blocks_needed; i++) {
        new_inode.direct[i] = sb.data_region_start + data_blocks[i];
    }
    for (uint64_t i = blocks_needed; i < DIRECT_MAX; i++) {
        new_inode.direct[i] = 0;
    }
    
    new_inode.reserved_0 = 0;
    new_inode.reserved_1 = 0;
    new_inode.reserved_2 = 0;
    new_inode.proj_id = 321;
    new_inode.uid16_gid16 = 0;
    new_inode.xattr_ptr = 0;
    
    inode_crc_finalize(&new_inode);
    
    // Write new inode to inode table
    uint64_t inode_offset = sb.inode_table_start * BS + (new_inode_num - 1) * INODE_SIZE;
    fseek(output_fp, inode_offset, SEEK_SET);
    fwrite(&new_inode, sizeof(new_inode), 1, output_fp);
    
    // Write file data to data blocks
    for (uint64_t i = 0; i < blocks_needed; i++) {
        uint64_t data_offset = (sb.data_region_start + data_blocks[i]) * BS;
        fseek(output_fp, data_offset, SEEK_SET);
        
        uint8_t file_buffer[BS] = {0};
        size_t bytes_to_read = (file_size > BS) ? BS : file_size;
        fread(file_buffer, 1, bytes_to_read, file_fp);
        fwrite(file_buffer, 1, BS, output_fp);
        file_size -= bytes_to_read;
    }
    
    fclose(file_fp);
    
    // Update root directory to include new file
    // Read root inode
    inode_t root_inode;
    uint64_t root_inode_offset = sb.inode_table_start * BS + (ROOT_INO - 1) * INODE_SIZE;
    fseek(output_fp, root_inode_offset, SEEK_SET);
    fread(&root_inode, sizeof(root_inode), 1, output_fp);
    
    // Read root directory data
    uint64_t root_data_offset = root_inode.direct[0] * BS;
    fseek(output_fp, root_data_offset, SEEK_SET);
    uint8_t root_data[BS];
    fread(root_data, 1, BS, output_fp);
    
    // Find free directory entry slot
    int entry_count = root_inode.size_bytes / sizeof(dirent64_t);
    dirent64_t *entries = (dirent64_t*)root_data;
    
    // Create new directory entry
    dirent64_t new_entry = {0};
    new_entry.inode_no = new_inode_num;
    new_entry.type = 1;
    strncpy(new_entry.name, file_name, 57);
    new_entry.name[57] = '\0';
    dirent_checksum_finalize(&new_entry);
    
    // Add entry to directory
    memcpy(&entries[entry_count], &new_entry, sizeof(new_entry));
    
    // Update root inode
    root_inode.size_bytes += sizeof(dirent64_t);
    root_inode.links++;
    root_inode.mtime = now;
    inode_crc_finalize(&root_inode);
    
    // Write updated root inode
    fseek(output_fp, root_inode_offset, SEEK_SET);
    fwrite(&root_inode, sizeof(root_inode), 1, output_fp);
    
    // Write updated root directory data
    fseek(output_fp, root_data_offset, SEEK_SET);
    fwrite(root_data, 1, BS, output_fp);
    
    fclose(output_fp);
    
    printf("File %s added successfully to filesystem %s\n", file_name, output_name);
    return 0;
}

int main(int argc, char *argv[]) {
    crc32_init();
    
    cli_args_t args;
    if (parse_args(argc, argv, &args) != 0) {
        return 1;
    }
    
    if (add_file_to_filesystem(args.input_name, args.output_name, args.file_name) != 0) {
        return 1;
    }
    
    return 0;
}
