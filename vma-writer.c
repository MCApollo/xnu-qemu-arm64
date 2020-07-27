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

#include "vma.h"
#include "block/block.h"
#include "monitor/monitor.h"
#include "qemu/main-loop.h"
#include "qemu/coroutine.h"
#include "qemu/cutils.h"

#define DEBUG_VMA 0

#define DPRINTF(fmt, ...)\
    do { if (DEBUG_VMA) { printf("vma: " fmt, ## __VA_ARGS__); } } while (0)

#define WRITE_BUFFERS 5
#define HEADER_CLUSTERS 8
#define HEADERBUF_SIZE (VMA_CLUSTER_SIZE*HEADER_CLUSTERS)

struct VmaWriter {
    int fd;
    FILE *cmd;
    int status;
    char errmsg[8192];
    uuid_t uuid;
    bool header_written;
    bool closed;

    /* we always write extents */
    unsigned char *outbuf;
    int outbuf_pos; /* in bytes */
    int outbuf_count; /* in VMA_BLOCKS */
    uint64_t outbuf_block_info[VMA_BLOCKS_PER_EXTENT];

    unsigned char *headerbuf;

    GChecksum *md5csum;
    CoMutex flush_lock;
    Coroutine *co_writer;

    /* drive informations */
    VmaStreamInfo stream_info[256];
    guint stream_count;

    guint8 vmstate_stream;
    uint32_t vmstate_clusters;

    /* header blob table */
    char *header_blob_table;
    uint32_t header_blob_table_size;
    uint32_t header_blob_table_pos;

    /* store for config blobs */
    uint32_t config_names[VMA_MAX_CONFIGS]; /* offset into blob_buffer table */
    uint32_t config_data[VMA_MAX_CONFIGS];  /* offset into blob_buffer table */
    uint32_t config_count;
};

void vma_writer_set_error(VmaWriter *vmaw, const char *fmt, ...)
{
    va_list ap;

    if (vmaw->status < 0) {
        return;
    }

    vmaw->status = -1;

    va_start(ap, fmt);
    g_vsnprintf(vmaw->errmsg, sizeof(vmaw->errmsg), fmt, ap);
    va_end(ap);

    DPRINTF("vma_writer_set_error: %s\n", vmaw->errmsg);
}

static uint32_t allocate_header_blob(VmaWriter *vmaw, const char *data,
                                     size_t len)
{
    if (len > 65535) {
        return 0;
    }

    if (!vmaw->header_blob_table ||
        (vmaw->header_blob_table_size <
         (vmaw->header_blob_table_pos + len + 2))) {
        int newsize = vmaw->header_blob_table_size + ((len + 2 + 511)/512)*512;

        vmaw->header_blob_table = g_realloc(vmaw->header_blob_table, newsize);
        memset(vmaw->header_blob_table + vmaw->header_blob_table_size,
               0, newsize - vmaw->header_blob_table_size);
        vmaw->header_blob_table_size = newsize;
    }

    uint32_t cpos = vmaw->header_blob_table_pos;
    vmaw->header_blob_table[cpos] = len & 255;
    vmaw->header_blob_table[cpos+1] = (len >> 8) & 255;
    memcpy(vmaw->header_blob_table + cpos + 2, data, len);
    vmaw->header_blob_table_pos += len + 2;
    return cpos;
}

static uint32_t allocate_header_string(VmaWriter *vmaw, const char *str)
{
    assert(vmaw);

    size_t len = strlen(str) + 1;

    return allocate_header_blob(vmaw, str, len);
}

int vma_writer_add_config(VmaWriter *vmaw, const char *name, gpointer data,
                          gsize len)
{
    assert(vmaw);
    assert(!vmaw->header_written);
    assert(vmaw->config_count < VMA_MAX_CONFIGS);
    assert(name);
    assert(data);

    gchar *basename = g_path_get_basename(name);
    uint32_t name_ptr = allocate_header_string(vmaw, basename);
    g_free(basename);

    if (!name_ptr) {
        return -1;
    }

    uint32_t data_ptr = allocate_header_blob(vmaw, data, len);
    if (!data_ptr) {
        return -1;
    }

    vmaw->config_names[vmaw->config_count] = name_ptr;
    vmaw->config_data[vmaw->config_count] = data_ptr;

    vmaw->config_count++;

    return 0;
}

int vma_writer_register_stream(VmaWriter *vmaw, const char *devname,
                               size_t size)
{
    assert(vmaw);
    assert(devname);
    assert(!vmaw->status);

    if (vmaw->header_written) {
        vma_writer_set_error(vmaw, "vma_writer_register_stream: header "
                             "already written");
        return -1;
    }

    guint n = vmaw->stream_count + 1;

    /* we can have dev_ids form 1 to 255 (0 reserved)
     * 255(-1) reseverd for safety
     */
    if (n > 254) {
        vma_writer_set_error(vmaw, "vma_writer_register_stream: "
                             "too many drives");
        return -1;
    }

    if (size <= 0) {
        vma_writer_set_error(vmaw, "vma_writer_register_stream: "
                             "got strange size %zd", size);
        return -1;
    }

    DPRINTF("vma_writer_register_stream %s %zu %d\n", devname, size, n);

    vmaw->stream_info[n].devname = g_strdup(devname);
    vmaw->stream_info[n].size = size;

    vmaw->stream_info[n].cluster_count = (size + VMA_CLUSTER_SIZE - 1) /
        VMA_CLUSTER_SIZE;

    vmaw->stream_count = n;

    if (strcmp(devname, "vmstate") == 0) {
        vmaw->vmstate_stream = n;
    }

    return n;
}

static void coroutine_fn yield_until_fd_writable(int fd)
{
    assert(qemu_in_coroutine());
    AioContext *ctx = qemu_get_current_aio_context();
    aio_set_fd_handler(ctx, fd, false, NULL, (IOHandler *)qemu_coroutine_enter,
                       NULL, qemu_coroutine_self());
    qemu_coroutine_yield();
    aio_set_fd_handler(ctx, fd, false, NULL, NULL, NULL, NULL);
}

static ssize_t coroutine_fn
vma_queue_write(VmaWriter *vmaw, const void *buf, size_t bytes)
{
    DPRINTF("vma_queue_write enter %zd\n", bytes);

    assert(vmaw);
    assert(buf);
    assert(bytes <= VMA_MAX_EXTENT_SIZE);

    size_t done = 0;
    ssize_t ret;

    assert(vmaw->co_writer == NULL);

    vmaw->co_writer = qemu_coroutine_self();

    while (done < bytes) {
        if (vmaw->status < 0) {
            DPRINTF("vma_queue_write detected canceled backup\n");
            done = -1;
            break;
        }
        yield_until_fd_writable(vmaw->fd);
        ret = write(vmaw->fd, buf + done, bytes - done);
        if (ret > 0) {
            done += ret;
            DPRINTF("vma_queue_write written %zd %zd\n", done, ret);
        } else if (ret < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* try again */
           } else {
                vma_writer_set_error(vmaw, "vma_queue_write: write error - %s",
                                     g_strerror(errno));
                done = -1; /* always return failure for partial writes */
                break;
            }
        } else if (ret == 0) {
            /* should not happen - simply try again */
        }
    }

    vmaw->co_writer = NULL;

    return (done == bytes) ? bytes : -1;
}

VmaWriter *vma_writer_create(const char *filename, uuid_t uuid, Error **errp)
{
    const char *p;

    assert(sizeof(VmaHeader) == (4096 + 8192));
    assert(G_STRUCT_OFFSET(VmaHeader, config_names) == 2044);
    assert(G_STRUCT_OFFSET(VmaHeader, config_data) == 3068);
    assert(G_STRUCT_OFFSET(VmaHeader, dev_info) == 4096);
    assert(sizeof(VmaExtentHeader) == 512);

    VmaWriter *vmaw = g_new0(VmaWriter, 1);
    vmaw->fd = -1;

    vmaw->md5csum = g_checksum_new(G_CHECKSUM_MD5);
    if (!vmaw->md5csum) {
        error_setg(errp, "can't allocate cmsum\n");
        goto err;
    }

    if (strstart(filename, "exec:", &p)) {
        vmaw->cmd = popen(p, "w");
        if (vmaw->cmd == NULL) {
            error_setg(errp, "can't popen command '%s' - %s\n", p,
                       g_strerror(errno));
            goto err;
        }
        vmaw->fd = fileno(vmaw->cmd);

        /* try to use O_NONBLOCK */
        fcntl(vmaw->fd, F_SETFL, fcntl(vmaw->fd, F_GETFL)|O_NONBLOCK);

    } else {
        struct stat st;
        int oflags;
        const char *tmp_id_str;

        if ((stat(filename, &st) == 0) && S_ISFIFO(st.st_mode)) {
            oflags = O_NONBLOCK|O_WRONLY;
            vmaw->fd = qemu_open(filename, oflags, 0644);
        } else if (strstart(filename, "/dev/fdset/", &tmp_id_str)) {
            oflags = O_NONBLOCK|O_WRONLY;
            vmaw->fd = qemu_open(filename, oflags, 0644);
        } else if (strstart(filename, "/dev/fdname/", &tmp_id_str)) {
            vmaw->fd = monitor_get_fd(cur_mon, tmp_id_str, errp);
            if (vmaw->fd < 0) {
                goto err;
            }
            /* try to use O_NONBLOCK */
            fcntl(vmaw->fd, F_SETFL, fcntl(vmaw->fd, F_GETFL)|O_NONBLOCK);
        } else  {
            oflags = O_NONBLOCK|O_DIRECT|O_WRONLY|O_CREAT|O_EXCL;
            vmaw->fd = qemu_open(filename, oflags, 0644);
        }

        if (vmaw->fd < 0) {
            error_setg(errp, "can't open file %s - %s\n", filename,
                       g_strerror(errno));
            goto err;
        }
    }

    /* we use O_DIRECT, so we need to align IO buffers */

    vmaw->outbuf = qemu_memalign(512, VMA_MAX_EXTENT_SIZE);
    vmaw->headerbuf = qemu_memalign(512, HEADERBUF_SIZE);

    vmaw->outbuf_count = 0;
    vmaw->outbuf_pos = VMA_EXTENT_HEADER_SIZE;

    vmaw->header_blob_table_pos = 1; /* start at pos 1 */

    qemu_co_mutex_init(&vmaw->flush_lock);

    uuid_copy(vmaw->uuid, uuid);

    return vmaw;

err:
    if (vmaw) {
        if (vmaw->cmd) {
            pclose(vmaw->cmd);
        } else if (vmaw->fd >= 0) {
            close(vmaw->fd);
        }

        if (vmaw->md5csum) {
            g_checksum_free(vmaw->md5csum);
        }

        g_free(vmaw);
    }

    return NULL;
}

static int coroutine_fn vma_write_header(VmaWriter *vmaw)
{
    assert(vmaw);
    unsigned char *buf = vmaw->headerbuf;
    VmaHeader *head = (VmaHeader *)buf;

    int i;

    DPRINTF("VMA WRITE HEADER\n");

    if (vmaw->status < 0) {
        return vmaw->status;
    }

    memset(buf, 0, HEADERBUF_SIZE);

    head->magic = VMA_MAGIC;
    head->version = GUINT32_TO_BE(1); /* v1 */
    memcpy(head->uuid, vmaw->uuid, 16);

    time_t ctime = time(NULL);
    head->ctime = GUINT64_TO_BE(ctime);

    for (i = 0; i < VMA_MAX_CONFIGS; i++) {
        head->config_names[i] = GUINT32_TO_BE(vmaw->config_names[i]);
        head->config_data[i] = GUINT32_TO_BE(vmaw->config_data[i]);
    }

    /* 32 bytes per device (12 used currently) = 8192 bytes max */
    for (i = 1; i <= 254; i++) {
        VmaStreamInfo *si = &vmaw->stream_info[i];
        if (si->size) {
            assert(si->devname);
            uint32_t devname_ptr = allocate_header_string(vmaw, si->devname);
            if (!devname_ptr) {
                return -1;
            }
            head->dev_info[i].devname_ptr = GUINT32_TO_BE(devname_ptr);
            head->dev_info[i].size = GUINT64_TO_BE(si->size);
        }
    }

    uint32_t header_size = sizeof(VmaHeader) + vmaw->header_blob_table_size;
    head->header_size = GUINT32_TO_BE(header_size);

    if (header_size > HEADERBUF_SIZE) {
        return -1; /* just to be sure */
    }

    uint32_t blob_buffer_offset = sizeof(VmaHeader);
    memcpy(buf + blob_buffer_offset, vmaw->header_blob_table,
           vmaw->header_blob_table_size);
    head->blob_buffer_offset = GUINT32_TO_BE(blob_buffer_offset);
    head->blob_buffer_size = GUINT32_TO_BE(vmaw->header_blob_table_pos);

    g_checksum_reset(vmaw->md5csum);
    g_checksum_update(vmaw->md5csum, (const guchar *)buf, header_size);
    gsize csize = 16;
    g_checksum_get_digest(vmaw->md5csum, (guint8 *)(head->md5sum), &csize);

    return vma_queue_write(vmaw, buf, header_size);
}

static int coroutine_fn vma_writer_flush(VmaWriter *vmaw)
{
    assert(vmaw);

    int ret;
    int i;

    if (vmaw->status < 0) {
        return vmaw->status;
    }

    if (!vmaw->header_written) {
        vmaw->header_written = true;
        ret = vma_write_header(vmaw);
        if (ret < 0) {
            vma_writer_set_error(vmaw, "vma_writer_flush: write header failed");
            return ret;
        }
    }

    DPRINTF("VMA WRITE FLUSH %d %d\n", vmaw->outbuf_count, vmaw->outbuf_pos);


    VmaExtentHeader *ehead = (VmaExtentHeader *)vmaw->outbuf;

    ehead->magic = VMA_EXTENT_MAGIC;
    ehead->reserved1 = 0;

    for (i = 0; i < VMA_BLOCKS_PER_EXTENT; i++) {
        ehead->blockinfo[i] = GUINT64_TO_BE(vmaw->outbuf_block_info[i]);
    }

    guint16 block_count = (vmaw->outbuf_pos - VMA_EXTENT_HEADER_SIZE) /
        VMA_BLOCK_SIZE;

    ehead->block_count = GUINT16_TO_BE(block_count);

    memcpy(ehead->uuid, vmaw->uuid, sizeof(ehead->uuid));
    memset(ehead->md5sum, 0, sizeof(ehead->md5sum));

    g_checksum_reset(vmaw->md5csum);
    g_checksum_update(vmaw->md5csum, vmaw->outbuf, VMA_EXTENT_HEADER_SIZE);
    gsize csize = 16;
    g_checksum_get_digest(vmaw->md5csum, ehead->md5sum, &csize);

    int bytes = vmaw->outbuf_pos;
    ret = vma_queue_write(vmaw, vmaw->outbuf, bytes);
    if (ret != bytes) {
        vma_writer_set_error(vmaw, "vma_writer_flush: failed write");
    }

    vmaw->outbuf_count = 0;
    vmaw->outbuf_pos = VMA_EXTENT_HEADER_SIZE;

    for (i = 0; i < VMA_BLOCKS_PER_EXTENT; i++) {
        vmaw->outbuf_block_info[i] = 0;
    }

    return vmaw->status;
}

static int vma_count_open_streams(VmaWriter *vmaw)
{
    g_assert(vmaw != NULL);

    int i;
    int open_drives = 0;
    for (i = 0; i <= 255; i++) {
        if (vmaw->stream_info[i].size && !vmaw->stream_info[i].finished) {
            open_drives++;
        }
    }

    return open_drives;
}


/**
 * You need to call this if the vma archive does not contain
 * any data stream.
 */
int coroutine_fn
vma_writer_flush_output(VmaWriter *vmaw)
{
    qemu_co_mutex_lock(&vmaw->flush_lock);
    int ret = vma_writer_flush(vmaw);
    qemu_co_mutex_unlock(&vmaw->flush_lock);
    if (ret < 0) {
        vma_writer_set_error(vmaw, "vma_writer_flush_header failed");
    }
    return ret;
}

/**
 * all jobs should call this when there is no more data
 * Returns: number of remaining stream (0 ==> finished)
 */
int coroutine_fn
vma_writer_close_stream(VmaWriter *vmaw, uint8_t dev_id)
{
    g_assert(vmaw != NULL);

    DPRINTF("vma_writer_set_status %d\n", dev_id);
    if (!vmaw->stream_info[dev_id].size) {
        vma_writer_set_error(vmaw, "vma_writer_close_stream: "
                             "no such stream %d", dev_id);
        return -1;
    }
    if (vmaw->stream_info[dev_id].finished) {
        vma_writer_set_error(vmaw, "vma_writer_close_stream: "
                             "stream already closed %d", dev_id);
        return -1;
    }

    vmaw->stream_info[dev_id].finished = true;

    int open_drives = vma_count_open_streams(vmaw);

    if (open_drives <= 0) {
        DPRINTF("vma_writer_set_status all drives completed\n");
        vma_writer_flush_output(vmaw);
    }

    return open_drives;
}

int vma_writer_get_status(VmaWriter *vmaw, VmaStatus *status)
{
    int i;

    g_assert(vmaw != NULL);

    if (status) {
        status->status = vmaw->status;
        g_strlcpy(status->errmsg, vmaw->errmsg, sizeof(status->errmsg));
        for (i = 0; i <= 255; i++) {
            status->stream_info[i] = vmaw->stream_info[i];
        }

        uuid_unparse_lower(vmaw->uuid, status->uuid_str);
    }

    status->closed = vmaw->closed;

    return vmaw->status;
}

static int vma_writer_get_buffer(VmaWriter *vmaw)
{
    int ret = 0;

    qemu_co_mutex_lock(&vmaw->flush_lock);

    /* wait until buffer is available */
    while (vmaw->outbuf_count >= (VMA_BLOCKS_PER_EXTENT - 1)) {
        ret = vma_writer_flush(vmaw);
        if (ret < 0) {
            vma_writer_set_error(vmaw, "vma_writer_get_buffer: flush failed");
            break;
        }
    }

    qemu_co_mutex_unlock(&vmaw->flush_lock);

    return ret;
}


int64_t coroutine_fn
vma_writer_write(VmaWriter *vmaw, uint8_t dev_id, int64_t cluster_num,
                 const unsigned char *buf, size_t *zero_bytes)
{
    g_assert(vmaw != NULL);
    g_assert(zero_bytes != NULL);

    *zero_bytes = 0;

    if (vmaw->status < 0) {
        return vmaw->status;
    }

    if (!dev_id || !vmaw->stream_info[dev_id].size) {
        vma_writer_set_error(vmaw, "vma_writer_write: "
                             "no such stream %d", dev_id);
        return -1;
    }

    if (vmaw->stream_info[dev_id].finished) {
        vma_writer_set_error(vmaw, "vma_writer_write: "
                             "stream already closed %d", dev_id);
        return -1;
    }


    if (cluster_num >= (((uint64_t)1)<<32)) {
        vma_writer_set_error(vmaw, "vma_writer_write: "
                             "cluster number out of range");
        return -1;
    }

    if (dev_id == vmaw->vmstate_stream) {
        if (cluster_num != vmaw->vmstate_clusters) {
            vma_writer_set_error(vmaw, "vma_writer_write: "
                                 "non sequential vmstate write");
        }
        vmaw->vmstate_clusters++;
    } else if (cluster_num >= vmaw->stream_info[dev_id].cluster_count) {
        vma_writer_set_error(vmaw, "vma_writer_write: cluster number too big");
        return -1;
    }

    /* wait until buffer is available */
    if (vma_writer_get_buffer(vmaw) < 0) {
        vma_writer_set_error(vmaw, "vma_writer_write: "
                             "vma_writer_get_buffer failed");
        return -1;
    }

    DPRINTF("VMA WRITE %d %zd\n", dev_id, cluster_num);

    uint64_t dev_size = vmaw->stream_info[dev_id].size;
    uint16_t mask = 0;

    if (buf) {
        int i;
        int bit = 1;
        uint64_t byte_offset = cluster_num * VMA_CLUSTER_SIZE;
        for (i = 0; i < 16; i++) {
            const unsigned char *vmablock = buf + (i*VMA_BLOCK_SIZE);

            // Note: If the source is not 64k-aligned, we might reach 4k blocks
            // after the end of the device. Always mark these as zero in the
            // mask, so the restore handles them correctly.
            if (byte_offset < dev_size &&
                !buffer_is_zero(vmablock, VMA_BLOCK_SIZE))
            {
                mask |= bit;
                memcpy(vmaw->outbuf + vmaw->outbuf_pos, vmablock,
                       VMA_BLOCK_SIZE);

                // prevent memory leakage on unaligned last block
                if (byte_offset + VMA_BLOCK_SIZE > dev_size) {
                    uint64_t real_data_in_block = dev_size - byte_offset;
                    memset(vmaw->outbuf + vmaw->outbuf_pos + real_data_in_block,
                           0, VMA_BLOCK_SIZE - real_data_in_block);
                }

                vmaw->outbuf_pos += VMA_BLOCK_SIZE;
            } else {
                DPRINTF("VMA WRITE %zd ZERO BLOCK %d\n", cluster_num, i);
                vmaw->stream_info[dev_id].zero_bytes += VMA_BLOCK_SIZE;
                *zero_bytes += VMA_BLOCK_SIZE;
            }

            byte_offset += VMA_BLOCK_SIZE;
            bit = bit << 1;
        }
    } else {
        DPRINTF("VMA WRITE %zd ZERO CLUSTER\n", cluster_num);
        vmaw->stream_info[dev_id].zero_bytes += VMA_CLUSTER_SIZE;
        *zero_bytes += VMA_CLUSTER_SIZE;
    }

    uint64_t block_info = ((uint64_t)mask) << (32+16);
    block_info |= ((uint64_t)dev_id) << 32;
    block_info |= (cluster_num & 0xffffffff);
    vmaw->outbuf_block_info[vmaw->outbuf_count] = block_info;

    DPRINTF("VMA WRITE MASK %zd %zx\n", cluster_num, block_info);

    vmaw->outbuf_count++;

    /** NOTE: We allways write whole clusters, but we correctly set
     * transferred bytes. So transferred == size when when everything
     * went OK.
     */
    size_t transferred = VMA_CLUSTER_SIZE;

    if (dev_id != vmaw->vmstate_stream) {
        uint64_t last = (cluster_num + 1) * VMA_CLUSTER_SIZE;
        if (last > dev_size) {
            uint64_t diff = last - dev_size;
            if (diff >= VMA_CLUSTER_SIZE) {
                vma_writer_set_error(vmaw, "vma_writer_write: "
                                     "read after last cluster");
                return -1;
            }
            transferred -= diff;
        }
    }

    vmaw->stream_info[dev_id].transferred += transferred;

    return transferred;
}

void vma_writer_error_propagate(VmaWriter *vmaw, Error **errp)
{
    if (vmaw->status < 0 && *errp == NULL) {
        error_setg(errp, "%s", vmaw->errmsg);
    }
}

int vma_writer_close(VmaWriter *vmaw, Error **errp)
{
    g_assert(vmaw != NULL);

    int i;

    qemu_co_mutex_lock(&vmaw->flush_lock); // wait for pending writes

    assert(vmaw->co_writer == NULL);

    if (vmaw->cmd) {
        if (pclose(vmaw->cmd) < 0) {
            vma_writer_set_error(vmaw, "vma_writer_close: "
                                 "pclose failed - %s", g_strerror(errno));
        }
    } else {
        if (close(vmaw->fd) < 0) {
            vma_writer_set_error(vmaw, "vma_writer_close: "
                                 "close failed - %s", g_strerror(errno));
        }
    }

    for (i = 0; i <= 255; i++) {
        VmaStreamInfo *si = &vmaw->stream_info[i];
        if (si->size) {
            if (!si->finished) {
                vma_writer_set_error(vmaw, "vma_writer_close: "
                                     "detected open stream '%s'", si->devname);
            } else if ((si->transferred != si->size) &&
                       (i != vmaw->vmstate_stream)) {
                vma_writer_set_error(vmaw, "vma_writer_close: "
                                     "incomplete stream '%s' (%zd != %zd)",
                                     si->devname, si->transferred, si->size);
            }
        }
    }

    for (i = 0; i <= 255; i++) {
        vmaw->stream_info[i].finished = 1; /* mark as closed */
    }

    vmaw->closed = 1;

    if (vmaw->status < 0 && *errp == NULL) {
        error_setg(errp, "%s", vmaw->errmsg);
    }

    qemu_co_mutex_unlock(&vmaw->flush_lock);

    return vmaw->status;
}

void vma_writer_destroy(VmaWriter *vmaw)
{
    assert(vmaw);

    int i;

    for (i = 0; i <= 255; i++) {
        if (vmaw->stream_info[i].devname) {
            g_free(vmaw->stream_info[i].devname);
        }
    }

    if (vmaw->md5csum) {
        g_checksum_free(vmaw->md5csum);
    }

    qemu_vfree(vmaw->headerbuf);
    qemu_vfree(vmaw->outbuf);
    g_free(vmaw);
}
