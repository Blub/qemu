/*
 * Core Definitions for QAPI Visitor Classes
 *
 * Copyright (C) 2012-2016 Red Hat, Inc.
 * Copyright IBM, Corp. 2011
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qapi/qmp/qobject.h"
#include "qapi/qmp/qerror.h"
#include "qapi/visitor.h"
#include "qapi/visitor-impl.h"

void visit_start_struct(Visitor *v, const char *name, void **obj,
                        const char *kind, size_t size, Error **errp)
{
    v->start_struct(v, obj, kind, name, size, errp);
}

void visit_end_struct(Visitor *v, Error **errp)
{
    v->end_struct(v, errp);
}

void visit_start_implicit_struct(Visitor *v, void **obj, size_t size,
                                 Error **errp)
{
    if (v->start_implicit_struct) {
        v->start_implicit_struct(v, obj, size, errp);
    }
}

void visit_end_implicit_struct(Visitor *v, Error **errp)
{
    if (v->end_implicit_struct) {
        v->end_implicit_struct(v, errp);
    }
}

void visit_start_list(Visitor *v, const char *name, Error **errp)
{
    v->start_list(v, name, errp);
}

GenericList *visit_next_list(Visitor *v, GenericList **list, Error **errp)
{
    return v->next_list(v, list, errp);
}

void visit_end_list(Visitor *v, Error **errp)
{
    v->end_list(v, errp);
}

bool visit_start_union(Visitor *v, bool data_present, Error **errp)
{
    if (v->start_union) {
        return v->start_union(v, data_present, errp);
    }
    return true;
}

bool visit_optional(Visitor *v, const char *name, bool *present)
{
    if (v->optional) {
        v->optional(v, present, name);
    }
    return *present;
}

void visit_get_next_type(Visitor *v, const char *name, QType *type,
                         bool promote_int, Error **errp)
{
    if (v->get_next_type) {
        v->get_next_type(v, type, promote_int, name, errp);
    }
}

void visit_type_enum(Visitor *v, const char *name, int *obj,
                     const char *const strings[], const char *kind,
                     Error **errp)
{
    v->type_enum(v, obj, strings, kind, name, errp);
}

void visit_type_int(Visitor *v, const char *name, int64_t *obj, Error **errp)
{
    v->type_int64(v, obj, name, errp);
}

static void visit_type_uintN(Visitor *v, uint64_t *obj, const char *name,
                             uint64_t max, const char *type, Error **errp)
{
    Error *err = NULL;
    uint64_t value = *obj;

    v->type_uint64(v, &value, name, &err);
    if (err) {
        error_propagate(errp, err);
    } else if (value > max) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   name ? name : "null", type);
    } else {
        *obj = value;
    }
}

void visit_type_uint8(Visitor *v, const char *name, uint8_t *obj,
                      Error **errp)
{
    uint64_t value = *obj;
    visit_type_uintN(v, &value, name, UINT8_MAX, "uint8_t", errp);
    *obj = value;
}

void visit_type_uint16(Visitor *v, const char *name, uint16_t *obj,
                       Error **errp)
{
    uint64_t value = *obj;
    visit_type_uintN(v, &value, name, UINT16_MAX, "uint16_t", errp);
    *obj = value;
}

void visit_type_uint32(Visitor *v, const char *name, uint32_t *obj,
                       Error **errp)
{
    uint64_t value = *obj;
    visit_type_uintN(v, &value, name, UINT32_MAX, "uint32_t", errp);
    *obj = value;
}

void visit_type_uint64(Visitor *v, const char *name, uint64_t *obj,
                       Error **errp)
{
    v->type_uint64(v, obj, name, errp);
}

static void visit_type_intN(Visitor *v, int64_t *obj, const char *name,
                            int64_t min, int64_t max, const char *type,
                            Error **errp)
{
    Error *err = NULL;
    int64_t value = *obj;

    v->type_int64(v, &value, name, &err);
    if (err) {
        error_propagate(errp, err);
    } else if (value < min || value > max) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   name ? name : "null", type);
    } else {
        *obj = value;
    }
}

void visit_type_int8(Visitor *v, const char *name, int8_t *obj, Error **errp)
{
    int64_t value = *obj;
    visit_type_intN(v, &value, name, INT8_MIN, INT8_MAX, "int8_t", errp);
    *obj = value;
}

void visit_type_int16(Visitor *v, const char *name, int16_t *obj,
                      Error **errp)
{
    int64_t value = *obj;
    visit_type_intN(v, &value, name, INT16_MIN, INT16_MAX, "int16_t", errp);
    *obj = value;
}

void visit_type_int32(Visitor *v, const char *name, int32_t *obj,
                      Error **errp)
{
    int64_t value = *obj;
    visit_type_intN(v, &value, name, INT32_MIN, INT32_MAX, "int32_t", errp);
    *obj = value;
}

void visit_type_int64(Visitor *v, const char *name, int64_t *obj,
                      Error **errp)
{
    v->type_int64(v, obj, name, errp);
}

void visit_type_size(Visitor *v, const char *name, uint64_t *obj,
                     Error **errp)
{
    if (v->type_size) {
        v->type_size(v, obj, name, errp);
    } else {
        v->type_uint64(v, obj, name, errp);
    }
}

void visit_type_bool(Visitor *v, const char *name, bool *obj, Error **errp)
{
    v->type_bool(v, obj, name, errp);
}

void visit_type_str(Visitor *v, const char *name, char **obj, Error **errp)
{
    v->type_str(v, obj, name, errp);
}

void visit_type_number(Visitor *v, const char *name, double *obj,
                       Error **errp)
{
    v->type_number(v, obj, name, errp);
}

void visit_type_any(Visitor *v, const char *name, QObject **obj, Error **errp)
{
    v->type_any(v, obj, name, errp);
}

void output_type_enum(Visitor *v, int *obj, const char * const strings[],
                      const char *kind, const char *name,
                      Error **errp)
{
    int i = 0;
    int value = *obj;
    char *enum_str;

    assert(strings);
    while (strings[i++] != NULL);
    if (value < 0 || value >= i - 1) {
        error_setg(errp, QERR_INVALID_PARAMETER, name ? name : "null");
        return;
    }

    enum_str = (char *)strings[value];
    visit_type_str(v, name, &enum_str, errp);
}

void input_type_enum(Visitor *v, int *obj, const char * const strings[],
                     const char *kind, const char *name,
                     Error **errp)
{
    Error *local_err = NULL;
    int64_t value = 0;
    char *enum_str;

    assert(strings);

    visit_type_str(v, name, &enum_str, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    while (strings[value] != NULL) {
        if (strcmp(strings[value], enum_str) == 0) {
            break;
        }
        value++;
    }

    if (strings[value] == NULL) {
        error_setg(errp, QERR_INVALID_PARAMETER, enum_str);
        g_free(enum_str);
        return;
    }

    g_free(enum_str);
    *obj = value;
}
