/*
 * VMA: Virtual Machine Archive
 *
 * Copyright (C) Proxmox Server Solutions
 *
 * Authors:
 *  Dietmar Maurer (dietmar@proxmox.com)
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef BACKUP_VMA_H
#define BACKUP_VMA_H

#include <uuid/uuid.h>
#include "qapi/error.h"
#include "block/block.h"

#define VMA_BLOCK_BITS 12
#define VMA_BLOCK_SIZE (1<<VMA_BLOCK_BITS)
#define VMA_CLUSTER_BITS (VMA_BLOCK_BITS+4)
#define VMA_CLUSTER_SIZE (1<<VMA_CLUSTER_BITS)

#if VMA_CLUSTER_SIZE != 65536
#error unexpected cluster size
#endif

#define VMA_EXTENT_HEADER_SIZE 512
#define VMA_BLOCKS_PER_EXTENT 59
#define VMA_MAX_CONFIGS 256

#define VMA_MAX_EXTENT_SIZE \
    (VMA_EXTENT_HEADER_SIZE+VMA_CLUSTER_SIZE*VMA_BLOCKS_PER_EXTENT)
#if VMA_MAX_EXTENT_SIZE != 3867136
#error unexpected VMA_EXTENT_SIZE
#endif

/* File Format Definitions */

#define VMA_MAGIC (GUINT32_TO_BE(('V'<<24)|('M'<<16)|('A'<<8)|0x00))
#define VMA_EXTENT_MAGIC (GUINT32_TO_BE(('V'<<24)|('M'<<16)|('A'<<8)|'E'))

typedef struct VmaDeviceInfoHeader {
    uint32_t devname_ptr; /* offset into blob_buffer table */
    uint32_t reserved0;
    uint64_t size; /* device size in bytes */
    uint64_t reserved1;
    uint64_t reserved2;
} VmaDeviceInfoHeader;

typedef struct VmaHeader {
    uint32_t magic;
    uint32_t version;
    unsigned char uuid[16];
    int64_t ctime;
    unsigned char md5sum[16];

    uint32_t blob_buffer_offset;
    uint32_t blob_buffer_size;
    uint32_t header_size;

    unsigned char reserved[1984];

    uint32_t config_names[VMA_MAX_CONFIGS]; /* offset into blob_buffer table */
    uint32_t config_data[VMA_MAX_CONFIGS];  /* offset into blob_buffer table */

    uint32_t reserved1;

    VmaDeviceInfoHeader dev_info[256];
} VmaHeader;

typedef struct VmaExtentHeader {
    uint32_t magic;
    uint16_t reserved1;
    uint16_t block_count;
    unsigned char uuid[16];
    unsigned char md5sum[16];
    uint64_t blockinfo[VMA_BLOCKS_PER_EXTENT];
} VmaExtentHeader;

/* functions/definitions to read/write vma files */

typedef struct VmaReader VmaReader;

typedef struct VmaWriter VmaWriter;

typedef struct VmaConfigData {
    const char *name;
    const void *data;
    uint32_t len;
} VmaConfigData;

typedef struct VmaStreamInfo {
    uint64_t size;
    uint64_t cluster_count;
    uint64_t transferred;
    uint64_t zero_bytes;
    int finished;
    char *devname;
} VmaStreamInfo;

typedef struct VmaStatus {
    int status;
    bool closed;
    char errmsg[8192];
    char uuid_str[37];
    VmaStreamInfo stream_info[256];
} VmaStatus;

typedef struct VmaDeviceInfo {
    uint64_t size; /* device size in bytes */
    const char *devname;
} VmaDeviceInfo;

VmaWriter *vma_writer_create(const char *filename, uuid_t uuid, Error **errp);
int vma_writer_close(VmaWriter *vmaw, Error **errp);
void vma_writer_error_propagate(VmaWriter *vmaw, Error **errp);
void vma_writer_destroy(VmaWriter *vmaw);
int vma_writer_add_config(VmaWriter *vmaw, const char *name, gpointer data,
                          size_t len);
int vma_writer_register_stream(VmaWriter *vmaw, const char *devname,
                               size_t size);

int64_t coroutine_fn vma_writer_write(VmaWriter *vmaw, uint8_t dev_id,
                                      int64_t cluster_num,
                                      const unsigned char *buf,
                                      size_t *zero_bytes);

int coroutine_fn vma_writer_close_stream(VmaWriter *vmaw, uint8_t dev_id);
int coroutine_fn vma_writer_flush_output(VmaWriter *vmaw);

int vma_writer_get_status(VmaWriter *vmaw, VmaStatus *status);
void vma_writer_set_error(VmaWriter *vmaw, const char *fmt, ...);


VmaReader *vma_reader_create(const char *filename, Error **errp);
void vma_reader_destroy(VmaReader *vmar);
VmaHeader *vma_reader_get_header(VmaReader *vmar);
GList *vma_reader_get_config_data(VmaReader *vmar);
VmaDeviceInfo *vma_reader_get_device_info(VmaReader *vmar, guint8 dev_id);
int vma_reader_register_bs(VmaReader *vmar, guint8 dev_id,
                           BlockBackend *target, bool write_zeroes,
                           Error **errp);
int vma_reader_restore(VmaReader *vmar, int vmstate_fd, bool verbose,
                       Error **errp);
int vma_reader_verify(VmaReader *vmar, bool verbose, Error **errp);

#endif /* BACKUP_VMA_H */
