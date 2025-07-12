#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

struct json_value;

// Allocation
struct json_value *json_create_string(const char *s);
struct json_value *json_create_number(uint64_t n);
struct json_value *json_create_boolean(bool b);
struct json_value *json_create_object();
void json_free(struct json_value *value);

// Set
int json_object_push(struct json_value *parent, const char *key, struct json_value *child);

// Get
const char *json_string_get(const struct json_value *value);
const uint64_t *json_number_get(const struct json_value *value);
const bool *json_boolean_get(const struct json_value *value);
struct json_value *json_object_get(const struct json_value *value, const char *key);

// Conversion
struct json_value *json_parse(const char *in, size_t size);
int json_serialize(const struct json_value *value, char *out, size_t size);
