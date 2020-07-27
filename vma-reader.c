/*
 * VMA: Virtual Machine Archive
 *
 * Copyright (C) 2012 Proxmox Server Solutions
 *
 * Authors:
 *  Dietmar Maurer (dietmar@proxmox.com)
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include <glib.h>
#include <uuid/uuid.h>

#include "qemu-common.h"
#include "qemu/timer.h"
#include "qemu/ratelimit.h"
#include "vma.h"
#include "block/block.h"
#include "sysemu/block-backend.h"

static unsigned char zero_vma_block[VMA_BLOCK_SIZE];

typedef struct VmaRestoreState {
    BlockBackend *target;
    bool write_zeroes;
    unsigned long *bitmap;
    int bitmap_size;
}  VmaRestoreState;

struct VmaReader {
    int fd;
    GChecksum *md5csum;
    GHashTable *blob_hash;
    unsigned char *head_data;
    VmaDeviceInfo devinfo[256];
    VmaRestoreState rstate[256];
    GList *cdata_list;
    guint8 vmstate_stream;
    uint32_t vmstate_clusters;
    /* to show restore percentage if run with -v */
    time_t start_time;
    int64_t cluster_count;
    int64_t clusters_read;
    int64_t zero_cluster_data;
    int64_t partial_zero_cluster_data;
    int clusters_read_per;
};

static guint
g_int32_hash(gconstpointer v)
{
    return *(const uint32_t *)v;
}

static gboolean
g_int32_equal(gconstpointer v1, gconstpointer v2)
{
    return *((const uint32_t *)v1) == *((const uint32_t *)v2);
}

static int vma_reader_get_bitmap(VmaRestoreState *rstate, int64_t cluster_num)
{
    assert(rstate);
    assert(rstate->bitmap);

    unsigned long val, idx, bit;

    idx = cluster_num / BITS_PER_LONG;

    assert(rstate->bitmap_size > idx);

    bit = cluster_num % BITS_PER_LONG;
    val = rstate->bitmap[idx];

    return !!(val & (1UL << bit));
}

static void vma_reader_set_bitmap(VmaRestoreState *rstate, int64_t cluster_num,
                                  int dirty)
{
    assert(rstate);
    assert(rstate->bitmap);

    unsigned long val, idx, bit;

    idx = cluster_num / BITS_PER_LONG;

    assert(rstate->bitmap_size > idx);

    bit = cluster_num % BITS_PER_LONG;
    val = rstate->bitmap[idx];
    if (dirty) {
        if (!(val & (1UL << bit))) {
            val |= 1UL << bit;
        }
    } else {
        if (val & (1UL << bit)) {
            val &= ~(1UL << bit);
        }
    }
    rstate->bitmap[idx] = val;
}

typedef struct VmaBlob {
    uint32_t start;
    uint32_t len;
    void *data;
} VmaBlob;

static const VmaBlob *get_header_blob(VmaReader *vmar, uint32_t pos)
{
    assert(vmar);
    assert(vmar->blob_hash);

    return g_hash_table_lookup(vmar->blob_hash, &pos);
}

static const char *get_header_str(VmaReader *vmar, uint32_t pos)
{
    const VmaBlob *blob = get_header_blob(vmar, pos);
    if (!blob) {
        return NULL;
    }
    const char *res = (char *)blob->data;
    if (res[blob->len-1] != '\0') {
        return NULL;
    }
    return res;
}

static ssize_t
safe_read(int fd, unsigned char *buf, size_t count)
{
    ssize_t n;

    do {
        n = read(fd, buf, count);
    } while (n < 0 && errno == EINTR);

    return n;
}

static ssize_t
full_read(int fd, unsigned char *buf, size_t len)
{
    ssize_t n;
    size_t total;

    total = 0;

    while (len > 0) {
        n = safe_read(fd, buf, len);

        if (n == 0) {
            return total;
        }

        if (n <= 0) {
            break;
        }

        buf += n;
        total += n;
        len -= n;
    }

    if (len) {
        return -1;
    }

    return total;
}

void vma_reader_destroy(VmaReader *vmar)
{
    assert(vmar);

    if (vmar->fd >= 0) {
        close(vmar->fd);
    }

    if (vmar->cdata_list) {
        g_list_free(vmar->cdata_list);
    }

    int i;
    for (i = 1; i < 256; i++) {
        if (vmar->rstate[i].bitmap) {
            g_free(vmar->rstate[i].bitmap);
        }
    }

    if (vmar->md5csum) {
        g_checksum_free(vmar->md5csum);
    }

    if (vmar->blob_hash) {
        g_hash_table_destroy(vmar->blob_hash);
    }

    if (vmar->head_data) {
        g_free(vmar->head_data);
    }

    g_free(vmar);

};

static int vma_reader_read_head(VmaReader *vmar, Error **errp)
{
    assert(vmar);
    assert(errp);
    assert(*errp == NULL);

    unsigned char md5sum[16];
    int i;
    int ret = 0;

    vmar->head_data = g_malloc(sizeof(VmaHeader));

    if (full_read(vmar->fd, vmar->head_data, sizeof(VmaHeader)) !=
        sizeof(VmaHeader)) {
        error_setg(errp, "can't read vma header - %s",
                   errno ? g_strerror(errno) : "got EOF");
        return -1;
    }

    VmaHeader *h = (VmaHeader *)vmar->head_data;

    if (h->magic != VMA_MAGIC) {
        error_setg(errp, "not a vma file - wrong magic number");
        return -1;
    }

    uint32_t header_size = GUINT32_FROM_BE(h->header_size);
    int need = header_size - sizeof(VmaHeader);
    if (need <= 0) {
        error_setg(errp, "wrong vma header size %d", header_size);
        return -1;
    }

    vmar->head_data = g_realloc(vmar->head_data, header_size);
    h = (VmaHeader *)vmar->head_data;

    if (full_read(vmar->fd, vmar->head_data + sizeof(VmaHeader), need) !=
        need) {
        error_setg(errp, "can't read vma header data - %s",
                   errno ? g_strerror(errno) : "got EOF");
        return -1;
    }

    memcpy(md5sum, h->md5sum, 16);
    memset(h->md5sum, 0, 16);

    g_checksum_reset(vmar->md5csum);
    g_checksum_update(vmar->md5csum, vmar->head_data, header_size);
    gsize csize = 16;
    g_checksum_get_digest(vmar->md5csum, (guint8 *)(h->md5sum), &csize);

    if (memcmp(md5sum, h->md5sum, 16) != 0) {
        error_setg(errp, "wrong vma header chechsum");
        return -1;
    }

    /* we can modify header data after checksum verify */
    h->header_size = header_size;

    h->version = GUINT32_FROM_BE(h->version);
    if (h->version != 1) {
        error_setg(errp, "wrong vma version %d", h->version);
        return -1;
    }

    h->ctime = GUINT64_FROM_BE(h->ctime);
    h->blob_buffer_offset = GUINT32_FROM_BE(h->blob_buffer_offset);
    h->blob_buffer_size = GUINT32_FROM_BE(h->blob_buffer_size);

    uint32_t bstart = h->blob_buffer_offset + 1;
    uint32_t bend = h->blob_buffer_offset + h->blob_buffer_size;

    if (bstart <= sizeof(VmaHeader)) {
        error_setg(errp, "wrong vma blob buffer offset %d",
                   h->blob_buffer_offset);
        return -1;
    }

    if (bend > header_size) {
        error_setg(errp, "wrong vma blob buffer size %d/%d",
                   h->blob_buffer_offset, h->blob_buffer_size);
        return -1;
    }

    while ((bstart + 2) <= bend) {
        uint32_t size = vmar->head_data[bstart] +
            (vmar->head_data[bstart+1] << 8);
        if ((bstart + size + 2) <= bend) {
            VmaBlob *blob = g_new0(VmaBlob, 1);
            blob->start = bstart - h->blob_buffer_offset;
            blob->len = size;
            blob->data = vmar->head_data + bstart + 2;
            g_hash_table_insert(vmar->blob_hash, &blob->start, blob);
        }
        bstart += size + 2;
    }


    int count = 0;
    for (i = 1; i < 256; i++) {
        VmaDeviceInfoHeader *dih = &h->dev_info[i];
        uint32_t devname_ptr = GUINT32_FROM_BE(dih->devname_ptr);
        uint64_t size = GUINT64_FROM_BE(dih->size);
        const char *devname =  get_header_str(vmar, devname_ptr);

        if (size && devname) {
            count++;
            vmar->devinfo[i].size = size;
            vmar->devinfo[i].devname = devname;

            if (strcmp(devname, "vmstate") == 0) {
                vmar->vmstate_stream = i;
            }
        }
    }

    for (i = 0; i < VMA_MAX_CONFIGS; i++) {
        uint32_t name_ptr = GUINT32_FROM_BE(h->config_names[i]);
        uint32_t data_ptr = GUINT32_FROM_BE(h->config_data[i]);

        if (!(name_ptr && data_ptr)) {
            continue;
        }
        const char *name =  get_header_str(vmar, name_ptr);
        const VmaBlob *blob = get_header_blob(vmar, data_ptr);

        if (!(name && blob)) {
            error_setg(errp, "vma contains invalid data pointers");
            return -1;
        }

        VmaConfigData *cdata = g_new0(VmaConfigData, 1);
        cdata->name = name;
        cdata->data = blob->data;
        cdata->len = blob->len;

        vmar->cdata_list = g_list_append(vmar->cdata_list, cdata);
    }

    return ret;
};

VmaReader *vma_reader_create(const char *filename, Error **errp)
{
    assert(filename);
    assert(errp);

    VmaReader *vmar = g_new0(VmaReader, 1);

    if (strcmp(filename, "-") == 0) {
        vmar->fd = dup(0);
    } else {
        vmar->fd = open(filename, O_RDONLY);
    }

    if (vmar->fd < 0) {
        error_setg(errp, "can't open file %s - %s\n", filename,
                   g_strerror(errno));
        goto err;
    }

    vmar->md5csum = g_checksum_new(G_CHECKSUM_MD5);
    if (!vmar->md5csum) {
        error_setg(errp, "can't allocate cmsum\n");
        goto err;
    }

    vmar->blob_hash = g_hash_table_new_full(g_int32_hash, g_int32_equal,
                                            NULL, g_free);

    if (vma_reader_read_head(vmar, errp) < 0) {
        goto err;
    }

    return vmar;

err:
    if (vmar) {
        vma_reader_destroy(vmar);
    }

    return NULL;
}

VmaHeader *vma_reader_get_header(VmaReader *vmar)
{
    assert(vmar);
    assert(vmar->head_data);

    return (VmaHeader *)(vmar->head_data);
}

GList *vma_reader_get_config_data(VmaReader *vmar)
{
    assert(vmar);
    assert(vmar->head_data);

    return vmar->cdata_list;
}

VmaDeviceInfo *vma_reader_get_device_info(VmaReader *vmar, guint8 dev_id)
{
    assert(vmar);
    assert(dev_id);

    if (vmar->devinfo[dev_id].size && vmar->devinfo[dev_id].devname) {
        return &vmar->devinfo[dev_id];
    }

    return NULL;
}

static void allocate_rstate(VmaReader *vmar,  guint8 dev_id,
                            BlockBackend *target, bool write_zeroes)
{
    assert(vmar);
    assert(dev_id);

    vmar->rstate[dev_id].target = target;
    vmar->rstate[dev_id].write_zeroes = write_zeroes;

    int64_t size = vmar->devinfo[dev_id].size;

    int64_t bitmap_size = (size/BDRV_SECTOR_SIZE) +
        (VMA_CLUSTER_SIZE/BDRV_SECTOR_SIZE) * BITS_PER_LONG - 1;
    bitmap_size /= (VMA_CLUSTER_SIZE/BDRV_SECTOR_SIZE) * BITS_PER_LONG;

    vmar->rstate[dev_id].bitmap_size = bitmap_size;
    vmar->rstate[dev_id].bitmap = g_new0(unsigned long, bitmap_size);

    vmar->cluster_count += size/VMA_CLUSTER_SIZE;
}

int vma_reader_register_bs(VmaReader *vmar, guint8 dev_id, BlockBackend *target,
                           bool write_zeroes, Error **errp)
{
    assert(vmar);
    assert(target != NULL);
    assert(dev_id);
    assert(vmar->rstate[dev_id].target == NULL);

    int64_t size = blk_getlength(target);
    int64_t size_diff = size - vmar->devinfo[dev_id].size;

    /* storage types can have different size restrictions, so it
     * is not always possible to create an image with exact size.
     * So we tolerate a size difference up to 4MB.
     */
    if ((size_diff < 0) || (size_diff > 4*1024*1024)) {
        error_setg(errp, "vma_reader_register_bs for stream %s failed - "
                   "unexpected size %zd != %zd", vmar->devinfo[dev_id].devname,
                   size, vmar->devinfo[dev_id].size);
        return -1;
    }

    allocate_rstate(vmar, dev_id, target, write_zeroes);

    return 0;
}

static ssize_t safe_write(int fd, void *buf, size_t count)
{
    ssize_t n;

    do {
        n = write(fd, buf, count);
    } while (n < 0 && errno == EINTR);

    return n;
}

static size_t full_write(int fd, void *buf, size_t len)
{
    ssize_t n;
    size_t total;

    total = 0;

    while (len > 0) {
        n = safe_write(fd, buf, len);
        if (n < 0) {
            return n;
        }
        buf += n;
        total += n;
        len -= n;
    }

    if (len) {
        /* incomplete write ? */
        return -1;
    }

    return total;
}

static int restore_write_data(VmaReader *vmar, guint8 dev_id,
                              BlockBackend *target, int vmstate_fd,
                              unsigned char *buf, int64_t sector_num,
                              int nb_sectors, Error **errp)
{
    assert(vmar);

    if (dev_id == vmar->vmstate_stream) {
        if (vmstate_fd >= 0) {
            int len = nb_sectors * BDRV_SECTOR_SIZE;
            int res = full_write(vmstate_fd, buf, len);
            if (res < 0) {
                error_setg(errp, "write vmstate failed %d", res);
                return -1;
            }
        }
    } else {
        int res = blk_pwrite(target, sector_num * BDRV_SECTOR_SIZE, buf, nb_sectors * BDRV_SECTOR_SIZE, 0);
        if (res < 0) {
            error_setg(errp, "blk_pwrite to %s failed (%d)",
                       bdrv_get_device_name(blk_bs(target)), res);
            return -1;
        }
    }
    return 0;
}

static int restore_extent(VmaReader *vmar, unsigned char *buf,
                          int extent_size, int vmstate_fd,
                          bool verbose, bool verify, Error **errp)
{
    assert(vmar);
    assert(buf);

    VmaExtentHeader *ehead = (VmaExtentHeader *)buf;
    int start = VMA_EXTENT_HEADER_SIZE;
    int i;

    for (i = 0; i < VMA_BLOCKS_PER_EXTENT; i++) {
        uint64_t block_info = GUINT64_FROM_BE(ehead->blockinfo[i]);
        uint64_t cluster_num = block_info & 0xffffffff;
        uint8_t dev_id = (block_info >> 32) & 0xff;
        uint16_t mask = block_info >> (32+16);
        int64_t max_sector;

        if (!dev_id) {
            continue;
        }

        VmaRestoreState *rstate = &vmar->rstate[dev_id];
        BlockBackend *target = NULL;

        if (dev_id != vmar->vmstate_stream) {
            target = rstate->target;
            if (!verify && !target) {
                error_setg(errp, "got wrong dev id %d", dev_id);
                return -1;
            }

            if (vma_reader_get_bitmap(rstate, cluster_num)) {
                error_setg(errp, "found duplicated cluster %zd for stream %s",
                          cluster_num, vmar->devinfo[dev_id].devname);
                return -1;
            }
            vma_reader_set_bitmap(rstate, cluster_num, 1);

            max_sector = vmar->devinfo[dev_id].size/BDRV_SECTOR_SIZE;
        } else {
            max_sector = G_MAXINT64;
            if (cluster_num != vmar->vmstate_clusters) {
                error_setg(errp, "found out of order vmstate data");
                return -1;
            }
            vmar->vmstate_clusters++;
        }

        vmar->clusters_read++;

        if (verbose) {
            time_t duration = time(NULL) - vmar->start_time;
            int percent = (vmar->clusters_read*100)/vmar->cluster_count;
            if (percent != vmar->clusters_read_per) {
                printf("progress %d%% (read %zd bytes, duration %zd sec)\n",
                       percent, vmar->clusters_read*VMA_CLUSTER_SIZE,
                       duration);
                fflush(stdout);
                vmar->clusters_read_per = percent;
            }
        }

        /* try to write whole clusters to speedup restore */
        if (mask == 0xffff) {
            if ((start + VMA_CLUSTER_SIZE) > extent_size) {
                error_setg(errp, "short vma extent - too many blocks");
                return -1;
            }
            int64_t sector_num = (cluster_num * VMA_CLUSTER_SIZE) /
                BDRV_SECTOR_SIZE;
            int64_t end_sector = sector_num +
                VMA_CLUSTER_SIZE/BDRV_SECTOR_SIZE;

            if (end_sector > max_sector) {
                end_sector = max_sector;
            }

            if (end_sector <= sector_num) {
                error_setg(errp, "got wrong block address - write beyond end");
                return -1;
            }

            if (!verify) {
                int nb_sectors = end_sector - sector_num;
                if (restore_write_data(vmar, dev_id, target, vmstate_fd,
                                       buf + start, sector_num, nb_sectors,
                                       errp) < 0) {
                    return -1;
                }
            }

            start += VMA_CLUSTER_SIZE;
        } else {
            int j;
            int bit = 1;

            for (j = 0; j < 16; j++) {
                int64_t sector_num = (cluster_num*VMA_CLUSTER_SIZE +
                                      j*VMA_BLOCK_SIZE)/BDRV_SECTOR_SIZE;

                int64_t end_sector = sector_num +
                    VMA_BLOCK_SIZE/BDRV_SECTOR_SIZE;
                if (end_sector > max_sector) {
                    end_sector = max_sector;
                }

                if (mask & bit) {
                    if ((start + VMA_BLOCK_SIZE) > extent_size) {
                        error_setg(errp, "short vma extent - too many blocks");
                        return -1;
                    }

                    if (end_sector <= sector_num) {
                        error_setg(errp, "got wrong block address - "
                                   "write beyond end");
                        return -1;
                    }

                    if (!verify) {
                        int nb_sectors = end_sector - sector_num;
                        if (restore_write_data(vmar, dev_id, target, vmstate_fd,
                                               buf + start, sector_num,
                                               nb_sectors, errp) < 0) {
                            return -1;
                        }
                    }

                    start += VMA_BLOCK_SIZE;

                } else {


                    if (end_sector > sector_num) {
                        /* Todo: use bdrv_co_write_zeroes (but that need to
                         * be run inside coroutine?)
                         */
                        int nb_sectors = end_sector - sector_num;
                        int zero_size = BDRV_SECTOR_SIZE*nb_sectors;
                        vmar->zero_cluster_data += zero_size;
                        if (mask != 0) {
                            vmar->partial_zero_cluster_data += zero_size;
                        }

                        if (rstate->write_zeroes && !verify) {
                            if (restore_write_data(vmar, dev_id, target, vmstate_fd,
                                                   zero_vma_block, sector_num,
                                                   nb_sectors, errp) < 0) {
                                return -1;
                            }
                        }
                    }
                }

                bit = bit << 1;
            }
        }
    }

    if (start != extent_size) {
        error_setg(errp, "vma extent error - missing blocks");
        return -1;
    }

    return 0;
}

static int vma_reader_restore_full(VmaReader *vmar, int vmstate_fd,
                                   bool verbose, bool verify,
                                   Error **errp)
{
    assert(vmar);
    assert(vmar->head_data);

    int ret = 0;
    unsigned char buf[VMA_MAX_EXTENT_SIZE];
    int buf_pos = 0;
    unsigned char md5sum[16];
    VmaHeader *h = (VmaHeader *)vmar->head_data;

    vmar->start_time = time(NULL);

    while (1) {
        int bytes = full_read(vmar->fd, buf + buf_pos, sizeof(buf) - buf_pos);
        if (bytes < 0) {
            error_setg(errp, "read failed - %s", g_strerror(errno));
            return -1;
        }

        buf_pos += bytes;

        if (!buf_pos) {
            break; /* EOF */
        }

        if (buf_pos < VMA_EXTENT_HEADER_SIZE) {
            error_setg(errp, "read short extent (%d bytes)", buf_pos);
            return -1;
        }

        VmaExtentHeader *ehead = (VmaExtentHeader *)buf;

        /* extract md5sum */
        memcpy(md5sum, ehead->md5sum, sizeof(ehead->md5sum));
        memset(ehead->md5sum, 0, sizeof(ehead->md5sum));

        g_checksum_reset(vmar->md5csum);
        g_checksum_update(vmar->md5csum, buf, VMA_EXTENT_HEADER_SIZE);
        gsize csize = 16;
        g_checksum_get_digest(vmar->md5csum, ehead->md5sum, &csize);

        if (memcmp(md5sum, ehead->md5sum, 16) != 0) {
            error_setg(errp, "wrong vma extent header chechsum");
            return -1;
        }

        if (memcmp(h->uuid, ehead->uuid, sizeof(ehead->uuid)) != 0) {
            error_setg(errp, "wrong vma extent uuid");
            return -1;
        }

        if (ehead->magic != VMA_EXTENT_MAGIC || ehead->reserved1 != 0) {
            error_setg(errp, "wrong vma extent header magic");
            return -1;
        }

        int block_count = GUINT16_FROM_BE(ehead->block_count);
        int extent_size = VMA_EXTENT_HEADER_SIZE + block_count*VMA_BLOCK_SIZE;

        if (buf_pos < extent_size) {
            error_setg(errp, "short vma extent (%d < %d)", buf_pos,
                       extent_size);
            return -1;
        }

        if (restore_extent(vmar, buf, extent_size, vmstate_fd, verbose,
                           verify, errp) < 0) {
            return -1;
        }

        if (buf_pos > extent_size) {
            memmove(buf, buf + extent_size, buf_pos - extent_size);
            buf_pos = buf_pos - extent_size;
        } else {
            buf_pos = 0;
        }
    }

    bdrv_drain_all();

    int i;
    for (i = 1; i < 256; i++) {
        VmaRestoreState *rstate = &vmar->rstate[i];
        if (!rstate->target) {
            continue;
        }

        if (blk_flush(rstate->target) < 0) {
            error_setg(errp, "vma blk_flush %s failed",
                       vmar->devinfo[i].devname);
            return -1;
        }

        if (vmar->devinfo[i].size &&
            (strcmp(vmar->devinfo[i].devname, "vmstate") != 0)) {
            assert(rstate->bitmap);

            int64_t cluster_num, end;

            end = (vmar->devinfo[i].size + VMA_CLUSTER_SIZE - 1) /
                VMA_CLUSTER_SIZE;

            for (cluster_num = 0; cluster_num < end; cluster_num++) {
                if (!vma_reader_get_bitmap(rstate, cluster_num)) {
                    error_setg(errp, "detected missing cluster %zd "
                               "for stream %s", cluster_num,
                               vmar->devinfo[i].devname);
                    return -1;
                }
            }
        }
    }

    if (verbose) {
        if (vmar->clusters_read) {
            printf("total bytes read %zd, sparse bytes %zd (%.3g%%)\n",
                   vmar->clusters_read*VMA_CLUSTER_SIZE,
                   vmar->zero_cluster_data,
                   (double)(100.0*vmar->zero_cluster_data)/
                   (vmar->clusters_read*VMA_CLUSTER_SIZE));

            int64_t datasize = vmar->clusters_read*VMA_CLUSTER_SIZE-vmar->zero_cluster_data;
            if (datasize) { // this does not make sense for empty files
                printf("space reduction due to 4K zero blocks %.3g%%\n",
                       (double)(100.0*vmar->partial_zero_cluster_data) / datasize);
            }
        } else {
            printf("vma archive contains no image data\n");
        }
    }
    return ret;
}

int vma_reader_restore(VmaReader *vmar, int vmstate_fd, bool verbose,
                       Error **errp)
{
    return vma_reader_restore_full(vmar, vmstate_fd, verbose, false, errp);
}

int vma_reader_verify(VmaReader *vmar, bool verbose, Error **errp)
{
    guint8 dev_id;

    for (dev_id = 1; dev_id < 255; dev_id++) {
        if (vma_reader_get_device_info(vmar, dev_id)) {
            allocate_rstate(vmar, dev_id, NULL, false);
        }
    }

    return vma_reader_restore_full(vmar, -1, verbose, true, errp);
}

