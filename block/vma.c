/*
 * VMA archive backend for QEMU, container object
 *
 * Copyright (C) 2017 Proxmox Server Solutions GmbH
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */
#include <vma/vma.h>

#include "qemu/osdep.h"
#include "qemu/uuid.h"
#include "qemu-common.h"
#include "qapi/error.h"
#include "qapi/qmp/qerror.h"
#include "qapi/qmp/qstring.h"
#include "qom/object.h"
#include "qom/object_interfaces.h"
#include "block/block_int.h"

/* exported interface */
void vma_object_add_config_file(Object *obj, const char *name,
                                const char *contents, size_t len,
                                Error **errp);

#define TYPE_VMA_OBJECT "vma"
#define VMA_OBJECT(obj) \
    OBJECT_CHECK(VMAObjectState, (obj), TYPE_VMA_OBJECT)
#define VMA_OBJECT_GET_CLASS(obj) \
    OBJECT_GET_CLASS(VMAObjectClass, (obj), TYPE_VMA_OBJECT)

typedef struct VMAObjectClass {
    ObjectClass parent_class;
} VMAObjectClass;

typedef struct VMAObjectState {
    Object parent;

    char        *filename;

    QemuUUID     uuid;
    bool         blocked;
    VMAWriter   *vma;
    QemuMutex    mutex;
} VMAObjectState;

static VMAObjectState *vma_by_id(const char *name)
{
    Object *container;
    Object *obj;

    container = object_get_objects_root();
    obj = object_resolve_path_component(container, name);

    return VMA_OBJECT(obj);
}

static void vma_object_class_complete(UserCreatable *uc, Error **errp)
{
    int rc;
    VMAObjectState *vo = VMA_OBJECT(uc);
    VMAObjectClass *voc = VMA_OBJECT_GET_CLASS(uc);
    (void)!vo;
    (void)!voc;

    if (!vo->filename) {
        error_setg(errp, "Parameter 'filename' is required");
        return;
    }

    rc = VMAWriter_fopen(vo->filename, &vo->vma);
    if (rc < 0) {
        error_setg_errno(errp, -rc, "failed to create VMA archive");
        return;
    }

    rc = VMAWriter_set_uuid(vo->vma, vo->uuid.data, sizeof(vo->uuid.data));
    if (rc < 0) {
        error_setg_errno(errp, -rc, "failed to set UUID of VMA archive");
        return;
    }

    qemu_mutex_init(&vo->mutex);
}

static bool vma_object_can_be_deleted(UserCreatable *uc, Error **errp)
{
    //VMAObjectState *vo = VMA_OBJECT(uc);
    //if (!vo->vma) {
    //    return true;
    //}
    //return false;
    return true;
}

static void vma_object_class_init(ObjectClass *oc, void *data)
{
    UserCreatableClass *ucc = USER_CREATABLE_CLASS(oc);

    ucc->can_be_deleted = vma_object_can_be_deleted;
    ucc->complete = vma_object_class_complete;
}

static char *vma_object_get_filename(Object *obj, Error **errp)
{
    VMAObjectState *vo = VMA_OBJECT(obj);

    return g_strdup(vo->filename);
}

static void vma_object_set_filename(Object *obj, const char *str, Error **errp)
{
    VMAObjectState *vo = VMA_OBJECT(obj);

    if (vo->vma) {
        error_setg(errp, "filename cannot be changed after creation");
        return;
    }

    g_free(vo->filename);
    vo->filename = g_strdup(str);
}

static char *vma_object_get_uuid(Object *obj, Error **errp)
{
    VMAObjectState *vo = VMA_OBJECT(obj);

    return qemu_uuid_unparse_strdup(&vo->uuid);
}

static void vma_object_set_uuid(Object *obj, const char *str, Error **errp)
{
    VMAObjectState *vo = VMA_OBJECT(obj);

    if (vo->vma) {
        error_setg(errp, "uuid cannot be changed after creation");
        return;
    }

    qemu_uuid_parse(str, &vo->uuid);
}

static bool vma_object_get_blocked(Object *obj, Error **errp)
{
    VMAObjectState *vo = VMA_OBJECT(obj);

    return vo->blocked;
}

static void vma_object_set_blocked(Object *obj, bool blocked, Error **errp)
{
    VMAObjectState *vo = VMA_OBJECT(obj);

    (void)errp;

    vo->blocked = blocked;
}

void vma_object_add_config_file(Object *obj, const char *name,
                                const char *contents, size_t len,
                                Error **errp)
{
    int rc;
    VMAObjectState *vo = VMA_OBJECT(obj);

    if (!vo || !vo->vma) {
        error_setg(errp, "not a valid vma object to add config files to");
        return;
    }

    rc = VMAWriter_addConfigFile(vo->vma, name, contents, len);
    if (rc < 0) {
        error_setg_errno(errp, -rc, "failed to add config file to VMA");
        return;
    }
}

static void vma_object_init(Object *obj)
{
    VMAObjectState *vo = VMA_OBJECT(obj);
    (void)!vo;

    object_property_add_str(obj, "filename",
                            vma_object_get_filename, vma_object_set_filename,
                            NULL);
    object_property_add_str(obj, "uuid",
                            vma_object_get_uuid, vma_object_set_uuid,
                            NULL);
    object_property_add_bool(obj, "blocked",
                            vma_object_get_blocked, vma_object_set_blocked,
                            NULL);
}

static void vma_object_finalize(Object *obj)
{
    VMAObjectState *vo = VMA_OBJECT(obj);
    VMAObjectClass *voc = VMA_OBJECT_GET_CLASS(obj);
    (void)!voc;

    qemu_mutex_destroy(&vo->mutex);

    VMAWriter_destroy(vo->vma, true);
    g_free(vo->filename);
}

static const TypeInfo vma_object_info = {
    .name = TYPE_VMA_OBJECT,
    .parent = TYPE_OBJECT,
    .class_size = sizeof(VMAObjectClass),
    .class_init = vma_object_class_init,
    .instance_size = sizeof(VMAObjectState),
    .instance_init = vma_object_init,
    .instance_finalize = vma_object_finalize,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_USER_CREATABLE },
        { }
    }
};

static void register_types(void)
{
    type_register_static(&vma_object_info);
}

type_init(register_types);

typedef struct {
    VMAObjectState *vma_obj;
    char           *name;
    size_t          device_id;
    uint64_t        byte_size;
} BDRVVMAState;

static void qemu_vma_parse_filename(const char *filename, QDict *options,
                                    Error **errp)
{
    char *sep;

    sep = strchr(filename, '/');
    if (!sep || sep == filename) {
        error_setg(errp, "VMA filename should be <vma-object>/<device-name>");
        return;
    }

    qdict_put(options, "vma", qstring_from_substr(filename, 0, sep-filename-1));

    while (*sep && *sep == '/')
        ++sep;
    if (!*sep) {
        error_setg(errp, "missing device name\n");
        return;
    }

    qdict_put(options, "name", qstring_from_str(sep));
}

static QemuOptsList runtime_opts = {
    .name = "vma-drive",
    .head = QTAILQ_HEAD_INITIALIZER(runtime_opts.head),
    .desc = {
        {
            .name = "vma",
            .type = QEMU_OPT_STRING,
            .help = "VMA Object name",
        },
        {
            .name = "name",
            .type = QEMU_OPT_STRING,
            .help = "VMA device name",
        },
        {
            .name = BLOCK_OPT_SIZE,
            .type = QEMU_OPT_SIZE,
            .help = "Virtual disk size"
        },
        { /* end of list */ }
    },
};
static int qemu_vma_open(BlockDriverState *bs, QDict *options, int flags,
                         Error **errp)
{
    Error *local_err = NULL;
    BDRVVMAState *s = bs->opaque;
    QemuOpts *opts;
    const char *vma_id, *device_name;
    ssize_t dev_id;
    int64_t bytes = 0;
    int ret;

    opts = qemu_opts_create(&runtime_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, options, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        ret = -EINVAL;
        goto failed_opts;
    }

    bytes = ROUND_UP(qemu_opt_get_size_del(opts, BLOCK_OPT_SIZE, 0),
                     BDRV_SECTOR_SIZE);

    vma_id = qemu_opt_get(opts, "vma");
    device_name = qemu_opt_get(opts, "name");

    VMAObjectState *vma = vma_by_id(vma_id);
    if (!vma) {
        ret = -EINVAL;
        error_setg(errp, "no such VMA object: %s", vma_id);
        goto failed_opts;
    }

    dev_id = VMAWriter_findDevice(vma->vma, device_name);
    if (dev_id >= 0) {
        error_setg(errp, "drive already exists in VMA object");
        ret = -EIO;
        goto failed_opts;
    }

    dev_id = VMAWriter_addDevice(vma->vma, device_name, (uint64_t)bytes);
    if (dev_id < 0) {
        error_setg_errno(errp, -dev_id, "failed to add VMA device");
        ret = -EIO;
        goto failed_opts;
    }

    object_ref(OBJECT(vma));
    s->vma_obj = vma;
    s->name = g_strdup(device_name);
    s->device_id = (size_t)dev_id;
    s->byte_size = bytes;

    ret = 0;

failed_opts:
    qemu_opts_del(opts);
    return ret;
}

static void qemu_vma_close(BlockDriverState *bs)
{
    BDRVVMAState *s = bs->opaque;

    (void)VMAWriter_finishDevice(s->vma_obj->vma, s->device_id);
    object_unref(OBJECT(s->vma_obj));

    g_free(s->name);
}

static int64_t qemu_vma_getlength(BlockDriverState *bs)
{
    BDRVVMAState *s = bs->opaque;

    return s->byte_size;
}

static coroutine_fn int qemu_vma_co_writev(BlockDriverState *bs,
                                           int64_t sector_num,
                                           int nb_sectors,
                                           QEMUIOVector *qiov)
{
    size_t i;
    ssize_t rc;
    BDRVVMAState *s = bs->opaque;
    VMAObjectState *vo = s->vma_obj;
    off_t offset = sector_num * BDRV_SECTOR_SIZE;

    qemu_mutex_lock(&vo->mutex);
    if (vo->blocked) {
        return -EPERM;
    }
    for (i = 0; i != qiov->niov; ++i) {
        const struct iovec *v = &qiov->iov[i];
        size_t blocks = v->iov_len / VMA_BLOCK_SIZE;
        if (blocks * VMA_BLOCK_SIZE != v->iov_len) {
            return -EIO;
        }
        rc = VMAWriter_writeBlocks(vo->vma, s->device_id,
                                   v->iov_base, blocks, offset);
        if (errno) {
            return -errno;
        }
        if (rc != blocks) {
            return -EIO;
        }
        offset += v->iov_len;
    }
    qemu_mutex_unlock(&vo->mutex);
    return 0;
}

static int qemu_vma_get_info(BlockDriverState *bs, BlockDriverInfo *bdi)
{
    bdi->cluster_size = VMA_CLUSTER_SIZE;
    bdi->unallocated_blocks_are_zero = true;
    bdi->can_write_zeroes_with_unmap = false;
    return 0;
}

static BlockDriver bdrv_vma_drive = {
    .format_name                  = "vma-drive",
    .instance_size                = sizeof(BDRVVMAState),

#if 0
    .bdrv_create                  = qemu_vma_create,
    .create_opts                  = &qemu_vma_create_opts,
#endif

    .bdrv_parse_filename          = qemu_vma_parse_filename,
    .bdrv_file_open               = qemu_vma_open,

    .bdrv_close                   = qemu_vma_close,
    .bdrv_has_zero_init           = bdrv_has_zero_init_1,
    .bdrv_getlength               = qemu_vma_getlength,
    .bdrv_get_info                = qemu_vma_get_info,

    .bdrv_co_writev               = qemu_vma_co_writev,
};

static void bdrv_vma_init(void)
{
    bdrv_register(&bdrv_vma_drive);
}

block_init(bdrv_vma_init);
