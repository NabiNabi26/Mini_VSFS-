# MiniVSFS – File System Builder in C

This project implements a simplified inode-based file system (MiniVSFS) in C.  
Includes two CLI tools:

- **mkfs_builder** → Generates a raw MiniVSFS disk image
- **mkfs_adder** → Inserts files into the MiniVSFS file system image

## Features
- Superblock, inode bitmap, data bitmap
- Inode table + directory entries
- First-fit block allocation
- CRC checksums for metadata
- Root directory setup (`.` and `..`)
- Binary image generation and validation

## How to Run
```bash
gcc mkfs_builder.c -o mkfs_builder
gcc mkfs_adder.c -o mkfs_adder
