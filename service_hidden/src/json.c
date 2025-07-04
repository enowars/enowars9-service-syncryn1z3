#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "json.h"


// Types

enum json_type {
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
};

struct json_kv_pair {
    char *key;
    struct json_value *value;
};

struct json_value {
    enum json_type type;

    union {
        uint64_t number;
        char *string;

        struct {
            struct json_value **items;
            size_t count;
        } array;

        struct {
            struct json_kv_pair *pairs;
            size_t count;
        } object;
    };
};


// Forward declarations

static struct json_value *_json_parse(const char **input, const char *end);
static int _json_serialize(const struct json_value *v, char **out, char *end);


// Helper functions

static char *_parse_string(const char **in, const char *end) {
    char *result;
    char *s;
    const char *p = *in;
    
    if (*p != '"') {
        return NULL;
    }

    ++p;

    result = malloc(end - p + 1);
    if (!result) {
        return NULL;
    }

    s = result;

    while (p < end && *p && *p != '"') {
        if (*p == '\\') {
            ++p; // skip escaped character

            if (!(*p)) {
                return NULL;
            }
        }

        *s = *p;
        ++p;
        ++s;
    }

    if (*p != '"') {
        free(result);
        return NULL;
    }

    *s = '\0';
    ++p;
    ++s;

    *in = p;

    result = realloc(result, s - result);

    return result;
}

static int _serialize_string(const char *s, char **out, const char *end) {
    char *p = *out;

    if (s >= end) {
        return -1;
    }

    *p = '"';
    ++p;
    
    while (p < end && *s) {
        if (*s == '"' || *s == '\\') {
            // escape character
            *p = '\\';
            ++p;

            if (p >= end) {
                return -1;
            }
        }

        *p = *s;
        ++p;
        ++s;
    }

    if (s + 1 >= end) {
        return -1;
    }

    *p = '"';
    ++p;

    *out = p;
    
    return 0;
}


// Parsing

static struct json_value *_json_parse_number(const char **in, const char *end) {
    struct json_value *v;
    const char *p = *in;
    uint64_t n = 0;

    while (p < end) {
        if (*p < '0' || *p > '9') {
            break;
        }

        n = n * 10 + (*p - '0');
        ++p;
    }

    if (p == *in) {
        return NULL;
    }

    *in = p;

    return json_create_number(n);
}

static struct json_value *_json_parse_string(const char **in, const char *end) {
    struct json_value *v;
    char *s;

    s = _parse_string(in, end);
    if (!s) {
        return NULL;
    }

    v = malloc(sizeof(struct json_value));
    if (!v) {
        free(s);
        return NULL;
    }

    v->type = JSON_STRING;
    v->string = s;

    return v;
}

static struct json_value *_json_parse_array(const char **in, const char *end) {
    struct json_value *v;
    const char *p = *in;

    if (p + 2 > end) {
        return NULL;
    }

    if (*p != '[') {
        return NULL;
    }

    ++p;

    v = json_create_array();

    if (*p != ']') {
        do {
            struct json_value *item = _json_parse(&p, end);
            if (!item) {
                break;
            }

            if (json_array_push(v, item)) {
                json_free(item);
                goto out;
            }

            if (p >= end) {
                goto out;
            }

            if (*p != ',') {
                break;
            }
            
            ++p;
        } while (p < end);
    }

    if (*p != ']' || p >= end) {
        goto out;
    }

    ++p;

    *in = p;

    return v;

out:
    json_free(v);

    return NULL;
}

static struct json_value *_json_parse_object(const char **in, const char *end) {
    struct json_value *v;
    const char *p = *in;

    if (p + 2 > end) {
        return NULL;
    }

    if (*p != '{') {
        return NULL;
    }

    ++p;

    v = json_create_object();

    if (*p != '}') {
        do {
            char *key = _parse_string(&p, end);
            if (!key) {
                break;
            }

            if (p >= end || *(p++) != ':') {
                free(key);
                goto out;
            }

            struct json_value *value = _json_parse(&p, end);
            if (!value) {
                free(key);
                goto out;
            }

            if (json_object_push(v, key, value)) {
                free(key);
                json_free(value);
                goto out;
            }

            if (p >= end) {
                goto out;
            }

            if (*p != ',') {
                break;
            }
            
            ++p;
        } while (p < end);
    }

    if (*p != '}' || p >= end) {
        goto out;
    }

    ++p;

    *in = p;

    return v;

out:
    json_free(v);

    return NULL;
}

static struct json_value *_json_parse(const char **input, const char *end) {
    struct json_value *v = NULL;

    v = _json_parse_number(input, end);
    if (v) {
        return v;
    }

    v = _json_parse_string(input, end);
    if (v) {
        return v;
    }

    v = _json_parse_array(input, end);
    if (v) {
        return v;
    }

    v = _json_parse_object(input, end);
    if (v) {
        return v;
    }

    return NULL;
}


// Serialization

static int _json_serialize(const struct json_value *v, char **out, char *end) {
    int ret;

    char *p = *out;

    if (p >= end) {
        return -1;
    }

    switch (v->type) {
        case JSON_NUMBER: {
            ret = snprintf(p, end - p, "%lu", v->number);
            if (ret < 0) {
                return ret;
            }

            if (ret > end - p) {
                return -1;
            }

            p += ret;

            break;
        }

        case JSON_STRING: {
            ret = _serialize_string(v->string, &p, end);
            if (ret < 0) {
                return ret;
            }

            if (ret > end - p) {
                return -1;
            }

            p += ret;

            break;
        }

        case JSON_ARRAY: {
            *p = '[';
            ++p;

            for (int i = 0; i < v->array.count; ++i) {
                ret = _json_serialize(v->array.items[i], &p, end);
                if (ret < 0) {
                    return ret;
                }

                if (p == end) {
                    return -1;
                }

                if (i < v->array.count - 1) {
                    *p = ',';
                    ++p;
                }
            }

            *p = ']';
            ++p;

            break;
        }

        case JSON_OBJECT: {
            *p = '{';
            ++p;

            for (int i = 0; i < v->object.count; ++i) {
                ret = snprintf(p, end - p, "\"%s\":", v->object.pairs[i].key);
                if (ret < 0) {
                    return ret;
                }

                p += ret;

                ret = _json_serialize(v->object.pairs[i].value, &p, end);
                if (ret < 0) {
                    return ret;
                }

                if (p == end) {
                    return -1;
                }

                if (i < v->array.count - 1) {
                    *p = ',';
                    ++p;
                }
            }

            *p = '}';
            ++p;

            break;
        }
    }
    
    *out = p;
    
    return 0;
}

struct json_value *json_parse(const char *in, size_t size) {
    return _json_parse_object(&in, in + size);
}

int json_serialize(const struct json_value *v, char *out, size_t size) {
    int ret;
    char *p = out;
    
    ret = _json_serialize(v, &p, p + size);
    if (ret < 0) {
        return ret;
    }

    if (p < out + size) {
        *p = '\0';
    }

    return 0;
}


// Creation / Deletion

struct json_value *json_create_number(uint64_t n) {
    struct json_value *v;

    v = malloc(sizeof(struct json_value));
    if (!v) {
        return NULL;
    }

    v->type = JSON_NUMBER;
    v->number = n;

    return v;
}

struct json_value *json_create_string(const char *s) {
    struct json_value *v;
    char *copy;

    copy = malloc(strlen(s) + 1);
    if (!copy) {
        return NULL;
    }

    strcpy(copy, s);
    
    v = malloc(sizeof(struct json_value));
    if (!v) {
        free(copy);
        return NULL;
    }

    v->type = JSON_STRING;
    v->string = copy;

    return v;
}

struct json_value *json_create_array() {
    struct json_value *v;

    v = malloc(sizeof(struct json_value));
    if (!v) {
        return NULL;
    }

    v->type = JSON_ARRAY;
    v->array.items = NULL;
    v->array.count = 0;

    return v;
}

struct json_value *json_create_object() {
    struct json_value *v;

    v = malloc(sizeof(struct json_value));
    if (!v) {
        return NULL;
    }

    v->type = JSON_OBJECT;
    v->object.pairs = NULL;
    v->object.count = 0;

    return v;
}

void json_free(struct json_value *v) {
    if (!v) {
        return;
    }

    switch (v->type) {
        case JSON_STRING: {
            free(v->string);
            break;
        }

        case JSON_ARRAY: {
            for (int i = 0; i < v->array.count; i++) {
                json_free(v->array.items[i]);
            }

            free(v->array.items);
            break;
        }

        case JSON_OBJECT: {
            for (int i = 0; i < v->object.count; i++) {
                free(v->object.pairs[i].key);
                json_free(v->object.pairs[i].value);
            }

            free(v->object.pairs);
            break;
        }
    }

    free(v);
}


// Modify

int json_array_push(struct json_value *parent, struct json_value *child) {
    int count = parent->array.count;

    parent->array.items = realloc(parent->array.items, sizeof(struct json_value) * (count + 1));
    if (!parent->array.items) {
        return -1;
    }

    parent->array.items[count] = child;
    ++parent->array.count;

    return 0;
}

int json_object_push(struct json_value *parent, char *key, struct json_value *child) {
    int count = parent->object.count;

    parent->object.pairs = realloc(parent->object.pairs, sizeof(struct json_kv_pair) * (count + 1));
    if (!parent->object.pairs) {
        return -1;
    }

    parent->object.pairs[count].key = key;
    parent->object.pairs[count].value = child;
    ++parent->object.count;

    return 0;
}


// Access

uint64_t *json_number_get(struct json_value *v) {
    if (v->type != JSON_NUMBER) {
        return NULL;
    }

    return &v->number;
}

const char *json_string_get(struct json_value *v) {
    if (v->type != JSON_STRING) {
        return NULL;
    }

    return v->string;
}

struct json_value *json_array_get(struct json_value *v, int index) {
    if (v->type != JSON_ARRAY) {
        return NULL;
    }

    if (index >= v->array.count) {
        return NULL;
    }

    return v->array.items[index];
}

struct json_value *json_object_get(struct json_value *v, const char *key) {
    const size_t length = strlen(key) + 1;

    if (v->type != JSON_OBJECT) {
        return NULL;
    }

    for (int i; i < v->object.count; ++i) {
        if (!strncmp(v->object.pairs[i].key, key, length)) {
            return v->object.pairs[i].value;
        }
    }

    return NULL;
}
