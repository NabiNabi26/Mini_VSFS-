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
    char *image_name;
    uint64_t size_kib;
    uint64_t inode_count;
} cli_args_t;

// Function to parse command line arguments
int parse_args(int argc, char *argv[], cli_args_t *args) {
    if (argc != 7) {
        fprintf(stderr, "Usage: %s --image <file> --size-kib <size> --inodes <count>\n", argv[0]);
        return -1;
    }
    
    args->image_name = NULL;
    args->size_kib = 0;
    args->inode_count = 0;
    
    for (int i = 1; i < argc; i += 2) {
        if (strcmp(argv[i], "--image") == 0) {
            args->image_name = argv[i + 1];
        } else if (strcmp(argv[i], "--size-kib") == 0) {
            args->size_kib = strtoull(argv[i + 1], NULL, 10);
        } else if (strcmp(argv[i], "--inodes") == 0) {
            args->inode_count = strtoull(argv[i + 1], NULL, 10);
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            return -1;
        }
    }
    
    // Validate arguments
    if (!args->image_name) {
        fprintf(stderr, "Error: --image argument is required\n");
        return -1;
    }
    if (args->size_kib < 180 || args->size_kib > 4096 || args->size_kib % 4 != 0) {
        fprintf(stderr, "Error: size-kib must be between 180-4096 and multiple of 4\n");
        return -1;
    }
    if (args->inode_count < 128 || args->inode_count > 512) {
        fprintf(stderr, "Error: inodes must be between 128-512\n");
        return -1;
    }
    return 0;
}

// Function to set a bit in bitmap
void set_bit(uint8_t *bitmap, uint64_t bit_num) {
    uint64_t byte_num = bit_num / 8;
    uint8_t bit_offset = bit_num % 8;
    bitmap[byte_num] |= (1 << bit_offset);
}

// Function to create filesystem
int create_filesystem(const char *image_name, uint64_t size_kib, uint64_t inode_count) {
    FILE *fp = fopen(image_name, "wb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot create image file %s\n", image_name);
        return -1;
    }
    
    uint64_t total_blocks = (size_kib * 1024) / BS;
    uint64_t inode_table_blocks = (inode_count * INODE_SIZE + BS - 1) / BS;
    
    // Calculate layout
    uint64_t inode_bitmap_start = 1;
    uint64_t data_bitmap_start = 2;
    uint64_t inode_table_start = 3;
    uint64_t data_region_start = inode_table_start + inode_table_blocks;
    uint64_t data_region_blocks = total_blocks - data_region_start;
    
    time_t now = time(NULL);
    
    // Create superblock
    superblock_t sb = {0};
    sb.magic = 0x4D565346;
    sb.version = 1;
    sb.block_size = BS;
    sb.total_blocks = total_blocks;
    sb.inode_count = inode_count;
    sb.inode_bitmap_start = inode_bitmap_start;
    sb.inode_bitmap_blocks = 1;
    sb.data_bitmap_start = data_bitmap_start;
    sb.data_bitmap_blocks = 1;
    sb.inode_table_start = inode_table_start;
    sb.inode_table_blocks = inode_table_blocks;
    sb.data_region_start = data_region_start;
    sb.data_region_blocks = data_region_blocks;
    sb.root_inode = ROOT_INO;
    sb.mtime_epoch = now;
    sb.flags = 0;
    
    // Write superblock
    uint8_t superblock_block[BS] = {0};
    memcpy(superblock_block, &sb, sizeof(sb));
    superblock_crc_finalize((superblock_t*)superblock_block);
    fwrite(superblock_block, 1, BS, fp);
    
    // Create and write inode bitmap
    uint8_t inode_bitmap[BS] = {0};
    set_bit(inode_bitmap, 0); // Mark root inode (inode 1) as allocated
    fwrite(inode_bitmap, 1, BS, fp);
    
    // Create and write data bitmap
    uint8_t data_bitmap[BS] = {0};
    set_bit(data_bitmap, 0); // Mark first data block as allocated for root directory
    fwrite(data_bitmap, 1, BS, fp);
    
    // Create root inode
    inode_t root_inode = {0};
    root_inode.mode = 040000;
    root_inode.links = 2;
    root_inode.uid = 0;
    root_inode.gid = 0;
    root_inode.size_bytes = 2 * sizeof(dirent64_t);
    root_inode.atime = now;
    root_inode.mtime = now;
    root_inode.ctime = now;
    root_inode.direct[0] = data_region_start;
    for (int i = 1; i < DIRECT_MAX; i++) {
        root_inode.direct[i] = 0;
    }
    root_inode.reserved_0 = 0;
    root_inode.reserved_1 = 0;
    root_inode.reserved_2 = 0;
    root_inode.proj_id = 321;
    root_inode.uid16_gid16 = 0;
    root_inode.xattr_ptr = 0;
    
    // Write inode table
    uint8_t inode_block[BS] = {0};
    inode_crc_finalize(&root_inode);
    memcpy(inode_block, &root_inode, sizeof(root_inode));
    
    for (uint64_t i = 0; i < inode_table_blocks; i++) {
        fwrite(inode_block, 1, BS, fp);
        memset(inode_block, 0, BS); // Clear for subsequent blocks
    }
    
    // Create root directory entries
    dirent64_t dot_entry = {0};
    dot_entry.inode_no = ROOT_INO;
    dot_entry.type = 2;
    strcpy(dot_entry.name, ".");
    dirent_checksum_finalize(&dot_entry);
    
    dirent64_t dotdot_entry = {0};
    dotdot_entry.inode_no = ROOT_INO;
    dotdot_entry.type = 2;
    strcpy(dotdot_entry.name, "..");
    dirent_checksum_finalize(&dotdot_entry);
    
    // Write root directory data block
    uint8_t root_data_block[BS] = {0};
    memcpy(root_data_block, &dot_entry, sizeof(dot_entry));
    memcpy(root_data_block + sizeof(dot_entry), &dotdot_entry, sizeof(dotdot_entry));
    fwrite(root_data_block, 1, BS, fp);
    
    // Write remaining data blocks
    uint8_t zero_block[BS] = {0};
    for (uint64_t i = 1; i < data_region_blocks; i++) {
        fwrite(zero_block, 1, BS, fp);
    }
    
    fclose(fp);
    printf("Filesystem created successfully: %s\n", image_name);
    return 0;
}

int main(int argc, char *argv[]) {
    crc32_init();
    
    cli_args_t args;
    if (parse_args(argc, argv, &args) != 0) {
        return 1;
    }
    
    if (create_filesystem(args.image_name, args.size_kib, args.inode_count) != 0) {
        return 1;
    }
    
    return 0;
}