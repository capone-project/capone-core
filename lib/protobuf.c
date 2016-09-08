/*
 * Copyright (C) 2016 Patrick Steinhardt
 * Copyright (C) 2014 Kevin Lyda <kevin@ie.suberic.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Sources have been taken and modified from the protobuf-c-text
 * project located at https://github.com/protobuf-c/protobuf-c-text.
 */

#include <protobuf-c/protobuf-c.h>

#include <string.h>
#include <ctype.h>

#include "capone/buf.h"

#define STRUCT_MEMBER(member_type, struct_p, struct_offset) \
    (*(member_type *) ((uint8_t *) (struct_p) + (struct_offset)))

static int escape(struct cpn_buf *buf, unsigned char *data, int len)
{
    int i, escapes = 0;

    for (i = 0; i < len; i++) {
        if (!isprint(data[i])) {
            escapes++;
        }
    }

    for (i = 0; i < len; i++) {
        switch (data[i]) {
            /* Special cases. */
            case '\'':
                cpn_buf_append(buf, "\\\'");
                break;
            case '\"':
                cpn_buf_append(buf, "\\\"");
                break;
            case '\\':
                cpn_buf_append(buf, "\\\\");
                break;
            case '\n':
                cpn_buf_append(buf, "\\n");
                break;
            case '\r':
                cpn_buf_append(buf, "\\r");
                break;
            case '\t':
                cpn_buf_append(buf, "\\t");
                break;

                /* Escape with octal if !isprint. */
            default:
                if (!isprint(data[i])) {
                    cpn_buf_printf(buf, "\\%03o", data[i]);
                } else {
                    cpn_buf_printf(buf, "%c", data[i]);
                }
                break;
        }
    }

    return 0;
}

/** Internal function to back API function.
 *
 * Has a few extra params to better enable recursion.  This function gets
 * called for each nested message as the \c ProtobufCMessage struct is
 * traversed.
 *
 * \param[in,out] rs The string being built up for the text format protobuf.
 * \param[in] level Indent level - increments in 2's.
 * \param[in] msg The \c ProtobufCMessage being serialised.
 */
int cpn_protobuf_to_string(struct cpn_buf *buf, int level, ProtobufCMessage *msg)
{
    unsigned int i;
    size_t j, quantifier_offset;
    double float_var;
    const ProtobufCFieldDescriptor *field;
    ProtobufCEnumDescriptor *enumd;
    const ProtobufCEnumValue *enumv;

    for (i = 0; i < msg->descriptor->n_fields; i++) {
        field = &msg->descriptor->fields[i];

        /* Decide if something needs to be done for this field. */
        switch (field->label) {
            case PROTOBUF_C_LABEL_OPTIONAL:
                if (field->type == PROTOBUF_C_TYPE_STRING) {
                    if (!STRUCT_MEMBER(char *, msg, field->offset)
                            || (STRUCT_MEMBER(char *, msg, field->offset)
                                == (char *)field->default_value)) {
                        continue;
                    }
                } else if (field->type == PROTOBUF_C_TYPE_MESSAGE) {
                    if (!STRUCT_MEMBER(char *, msg, field->offset)) {
                        continue;
                    }
                } else {
                    if (!STRUCT_MEMBER(protobuf_c_boolean, msg, field->quantifier_offset)) {
                        continue;
                    }
                }
                break;
            case PROTOBUF_C_LABEL_REPEATED:
                if (!STRUCT_MEMBER(size_t, msg, field->quantifier_offset)) {
                    continue;
                }
                break;
            case PROTOBUF_C_LABEL_REQUIRED:
                break;
        }

        quantifier_offset = STRUCT_MEMBER(size_t, msg, field->quantifier_offset);

        switch (field->type) {
            case PROTOBUF_C_TYPE_INT32:
            case PROTOBUF_C_TYPE_UINT32:
            case PROTOBUF_C_TYPE_FIXED32:
                if (field->label == PROTOBUF_C_LABEL_REPEATED) {
                    for (j = 0; j < quantifier_offset; j++) {
                        cpn_buf_printf(buf, "%*s%s: %u\n", level, "", field->name,
                                STRUCT_MEMBER(uint32_t *, msg, field->offset)[j]);
                    }
                } else {
                    cpn_buf_printf(buf, "%*s%s: %u\n", level, "", field->name,
                            STRUCT_MEMBER(uint32_t, msg, field->offset));
                }
                break;

            case PROTOBUF_C_TYPE_SINT32:
            case PROTOBUF_C_TYPE_SFIXED32:
                if (field->label == PROTOBUF_C_LABEL_REPEATED) {
                    for (j = 0; j < quantifier_offset; j++) {
                        cpn_buf_printf(buf, "%*s%s: %d\n", level, "", field->name,
                                STRUCT_MEMBER(int32_t *, msg, field->offset)[j]);
                    }
                } else {
                    cpn_buf_printf(buf, "%*s%s: %d\n", level, "", field->name,
                            STRUCT_MEMBER(int32_t, msg, field->offset));
                }
                break;

            case PROTOBUF_C_TYPE_INT64:
            case PROTOBUF_C_TYPE_UINT64:
            case PROTOBUF_C_TYPE_FIXED64:
                if (field->label == PROTOBUF_C_LABEL_REPEATED) {
                    for (j = 0; j < quantifier_offset; j++) {
                        cpn_buf_printf(buf, "%*s%s: %lu\n", level, "", field->name,
                                STRUCT_MEMBER(uint64_t *, msg, field->offset)[j]);
                    }
                } else {
                    cpn_buf_printf(buf, "%*s%s: %lu\n", level, "", field->name,
                            STRUCT_MEMBER(uint64_t, msg, field->offset));
                }
                break;

            case PROTOBUF_C_TYPE_SINT64:
            case PROTOBUF_C_TYPE_SFIXED64:
                if (field->label == PROTOBUF_C_LABEL_REPEATED) {
                    for (j = 0; j < quantifier_offset; j++) {
                        cpn_buf_printf(buf, "%*s%s: %ld\n", level, "", field->name,
                                STRUCT_MEMBER(int64_t *, msg, field->offset)[j]);
                    }
                } else {
                    cpn_buf_printf(buf, "%*s%s: %ld\n", level, "", field->name,
                            STRUCT_MEMBER(int64_t, msg, field->offset));
                }
                break;

            case PROTOBUF_C_TYPE_FLOAT:
                if (field->label == PROTOBUF_C_LABEL_REPEATED) {
                    for (j = 0; j < quantifier_offset; j++) {
                        float_var = STRUCT_MEMBER(float *, msg, field->offset)[j];
                        cpn_buf_printf(buf, "%*s%s: %g\n", level, "", field->name,
                                float_var);
                    }
                } else {
                    float_var = STRUCT_MEMBER(float, msg, field->offset);
                    cpn_buf_printf(buf, "%*s%s: %g\n", level, "", field->name,
                            float_var);
                }
                break;

            case PROTOBUF_C_TYPE_DOUBLE:
                if (field->label == PROTOBUF_C_LABEL_REPEATED) {
                    for (j = 0; j < quantifier_offset; j++) {
                        cpn_buf_printf(buf, "%*s%s: %g\n", level, "", field->name,
                                STRUCT_MEMBER(double *, msg, field->offset)[j]);
                    }
                } else {
                    cpn_buf_printf(buf, "%*s%s: %g\n", level, "", field->name,
                            STRUCT_MEMBER(double, msg, field->offset));
                }
                break;

            case PROTOBUF_C_TYPE_BOOL:
                if (field->label == PROTOBUF_C_LABEL_REPEATED) {
                    for (j = 0; j < quantifier_offset; j++) {
                        cpn_buf_printf(buf, "%*s%s: %s\n", level, "", field->name,
                                STRUCT_MEMBER(protobuf_c_boolean *, msg, field->offset)[j]?
                                "true": "false");
                    }
                } else {
                    cpn_buf_printf(buf, "%*s%s: %s\n", level, "", field->name,
                            STRUCT_MEMBER(protobuf_c_boolean, msg, field->offset)?
                            "true": "false");
                }
                break;

            case PROTOBUF_C_TYPE_ENUM:
                enumd = (ProtobufCEnumDescriptor *) field->descriptor;

                if (field->label == PROTOBUF_C_LABEL_REPEATED) {
                    for (j = 0; j < quantifier_offset; j++) {
                        enumv = protobuf_c_enum_descriptor_get_value(
                                enumd, STRUCT_MEMBER(int *, msg, field->offset)[j]);
                        cpn_buf_printf(buf, "%*s%s: %s\n", level, "", field->name,
                                enumv ? enumv->name: "unknown");
                    }
                } else {
                    enumv = protobuf_c_enum_descriptor_get_value(
                            enumd, STRUCT_MEMBER(int, msg, field->offset));
                    cpn_buf_printf(buf, "%*s%s: %s\n", level, "", field->name,
                            enumv ? enumv->name: "unknown");
                }
                break;

            case PROTOBUF_C_TYPE_STRING:
                if (field->label == PROTOBUF_C_LABEL_REPEATED) {
                    for (j = 0; j < quantifier_offset; j++) {
                        char *member = STRUCT_MEMBER(char **, msg, field->offset)[j];

                        cpn_buf_printf(buf, "%*s%s: ", level, "", field->name);
                        if (escape(buf, (unsigned char *) member, member ? strlen(member) : 0) < 0)
                            goto out_err;
                        cpn_buf_append(buf, "\n");
                    }
                } else {
                    char *member = STRUCT_MEMBER(char *, msg, field->offset);

                    cpn_buf_printf(buf, "%*s%s: ", level, "", field->name);
                    if (escape(buf, (unsigned char *) member, member ? strlen(member) : 0) < 0)
                        goto out_err;
                    cpn_buf_append(buf, "\n");
                }
                break;

            case PROTOBUF_C_TYPE_BYTES:
                if (field->label == PROTOBUF_C_LABEL_REPEATED) {
                    for (j = 0; j < quantifier_offset; j++) {
                        ProtobufCBinaryData *member =
                            &STRUCT_MEMBER(ProtobufCBinaryData *, msg, field->offset)[j];
                        cpn_buf_printf(buf, "%*s%s: ", level, "", field->name);
                        if (escape(buf, member->data, member->len) < 0)
                            goto out_err;
                        cpn_buf_append(buf, "\n");
                    }
                } else {
                    ProtobufCBinaryData *member = &STRUCT_MEMBER(ProtobufCBinaryData, msg, field->offset);
                    cpn_buf_printf(buf, "%*s%s: ", level, "", field->name);
                    if (escape(buf, member->data, member->len) < 0)
                        goto out_err;
                    cpn_buf_append(buf, "\n");
                }
                break;

            case PROTOBUF_C_TYPE_MESSAGE:
                if (field->label == PROTOBUF_C_LABEL_REPEATED) {
                    for (j = 0;
                            j < STRUCT_MEMBER(size_t, msg, field->quantifier_offset);
                            j++) {
                        cpn_buf_printf(buf, "%*s%s {\n", level, "", field->name);
                        cpn_protobuf_to_string(buf, level + 2,
                                STRUCT_MEMBER(ProtobufCMessage **, msg, field->offset)[j]);
                        cpn_buf_printf(buf, "%*s}\n", level, "");
                    }
                } else {
                    cpn_buf_printf(buf, "%*s%s {\n", level, "", field->name);
                    cpn_protobuf_to_string(buf, level + 2,
                            STRUCT_MEMBER(ProtobufCMessage *, msg, field->offset));
                    cpn_buf_printf(buf, "%*s}\n", level, "");
                }
                break;

            default:
                goto out_err;
        }
    }

    return 0;

out_err:
    return -1;
}
