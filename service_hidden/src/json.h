#pragma once

#include <stdlib.h>
#include <stdint.h>

struct json_value;

struct json_value *json_create_number(uint64_t n);
struct json_value *json_create_string(const char *s);
struct json_value *json_create_array();
struct json_value *json_create_object();

void json_free(struct json_value *value);

int json_array_push(struct json_value *parent, struct json_value *child);
int json_object_push(struct json_value *parent, char *key, struct json_value *child);

uint64_t *json_number_get(struct json_value *v);
const char *json_string_get(struct json_value *v);
struct json_value *json_array_get(struct json_value *v, int index);
struct json_value *json_object_get(struct json_value *v, const char *key);

struct json_value *json_parse(const char *in, size_t size);
int json_serialize(const struct json_value *v, char *out, size_t size);
