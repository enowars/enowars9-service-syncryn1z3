#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "string.h"
#include "json.h"


// Types

enum json_type {
    JSON_STRING,
    JSON_NUMBER,
    JSON_BOOLEAN,
    JSON_OBJECT,
#ifdef JSON_WITH_ARRAY
    JSON_ARRAY,
#endif
};

struct json_kv_pair {
    char *key;
    struct json_value *value;
};

struct json_value {
    enum json_type type;

    union {
        char *string;
        uint64_t number;
        bool boolean;

        struct {
            struct json_kv_pair *pairs;
            size_t count;
        } object;

#ifdef JSON_WITH_ARRAY
        struct {
            struct json_value **items;
            size_t count;
        } array;
#endif
    };
};


// Forward declarations

static struct json_value *_json_parse(const char **input, const char *end);
static int _json_serialize(const struct json_value *v, char **out, char *end);
static int _json_object_push(struct json_value *parent, char *key, struct json_value *child);

#ifdef JSON_WITH_ARRAY
struct json_value *json_create_array();
int json_array_push(struct json_value *parent, struct json_value *child);
#endif


// Helper functions

static int _skip_whitespace(const char **in, const char *end) {
    const char *p = *in;

    if (p >= end) {
        return -1;
    }

    while (*p == ' ' || *p == '\n') {
        ++p;

        if (p >= end) {
            return -1;
        }
    }

    *in = p;

    return 0;
}

static char *_parse_string(const char **in, const char *end) {
    char *result;
    char *s;
    
    if (_skip_whitespace(in, end)) {
        return NULL;
    }

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

            if (p >= end || !(*p)) {
                free(result);
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

    if (p >= end) {
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

    if (p + 1 >= end) {
        return -1;
    }

    *p = '"';
    ++p;

    *out = p;
    
    return 0;
}


// Parsing

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

static struct json_value *_json_parse_number(const char **in, const char *end) {
    uint64_t n = 0;

    if (_skip_whitespace(in, end)) {
        return NULL;
    }

    const char *p = *in;

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

static struct json_value *_json_parse_boolean(const char **in, const char *end) {
    int ret;

    if (_skip_whitespace(in, end)) {
        return NULL;
    }

    const char *p = *in;

    if (end <= p + sizeof("true") - 1) {
        return NULL;
    }

    ret = strncmp(p, "true", sizeof("true") - 1);
    if (!ret) {
        *in = p + sizeof("true") - 1;

        return json_create_boolean(true);
    }

    if (end <= p + sizeof("false") - 1) {
        return NULL;
    }

    ret = strncmp(p, "false", sizeof("false") - 1);
    if (!ret) {
        *in = p + sizeof("false") - 1;

        return json_create_boolean(false);
    }
    
    return NULL;
}

static struct json_value *_json_parse_object(const char **in, const char *end) {
    struct json_value *v;
    
    if (_skip_whitespace(in, end)) {
        return NULL;
    }

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

            if (_json_object_push(v, key, value)) {
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

    // We should also skip whitespace here, but I don't want to make the reversing too hard

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

#ifdef JSON_WITH_ARRAY
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
#endif

static struct json_value *_json_parse(const char **input, const char *end) {
    struct json_value *v = NULL;

    v = _json_parse_string(input, end);
    if (v) {
        return v;
    }

    v = _json_parse_number(input, end);
    if (v) {
        return v;
    }

    v = _json_parse_boolean(input, end);
    if (v) {
        return v;
    }

    v = _json_parse_object(input, end);
    if (v) {
        return v;
    }

#ifdef JSON_WITH_ARRAY
    v = _json_parse_array(input, end);
    if (v) {
        return v;
    }
#endif

    return NULL;
}


// Serialization

static int _json_serialize_string(const struct json_value *v, char **out, char *end) {
    return _serialize_string(v->string, out, end);
}

static int _json_serialize_number(const struct json_value *v, char **out, char *end) {
    char temp[20];

    int i = 0;
    uint64_t n = v->number;

    char *p = *out;

    if (v->number == 0) {
        temp[0] = '0';
        ++i;
    } else {
        // Convert to string in reverse order
        while (n > 0) {
            uint64_t digit = n % 10;

            temp[i] = '0' + (char)digit;
            n /= 10;
            ++i;
        }
    }

    char *digit_end = p + i;

    if (digit_end >= end) {
        return -1;
    }

    char *d = temp + i - 1;

    while (p < digit_end) {
        *p = *d;
        ++p;
        --d;
    }

    *out = p;

    return 0;
}

static int _json_serialize_boolean(const struct json_value *v, char **out, char *end) {
    char *p = *out;

    if (v->boolean) {
        if (p + 4 >= end) {
            return -1;
        }

        __builtin_strncpy(p, "true", 4);
        *out = p + 4;
    } else {
        if (p + 5 >= end) {
            return -1;
        }

        __builtin_strncpy(p, "false", 5);
        *out = p + 5;
    }

    return 0;
}

static int _json_serialize_object(const struct json_value *v, char **out, char *end) {
    int ret;

    char *p = *out;

    *p = '{';
    ++p;

    for (int i = 0; i < v->object.count; ++i) {
        ret = _serialize_string(v->object.pairs[i].key, &p, end);
        if (ret < 0) {
            return ret;
        }

        *p = ':';
        ++p;

        if (p + 1 >= end) {
            return -1;
        }

        ret = _json_serialize(v->object.pairs[i].value, &p, end);
        if (ret < 0) {
            return ret;
        }

        if (p + 1 >= end) {
            return -1;
        }

        if (i < v->object.count - 1) {
            *p = ',';
            ++p;
        }
    }

    *p = '}';
    ++p;

    *out = p;

    return 0;
}

#ifdef JSON_WITH_ARRAY
static int _json_serialize_array(const struct json_value *v, char **out, char *end) {
    int ret;

    char *p = *out;

    *p = '[';
    ++p;

    for (int i = 0; i < v->array.count; ++i) {
        ret = _json_serialize(v->array.items[i], &p, end);
        if (ret < 0) {
            return ret;
        }

        if (p + 1 >= end) {
            return -1;
        }

        if (i < v->array.count - 1) {
            *p = ',';
            ++p;
        }
    }

    *p = ']';
    ++p;

    *out = p;

    return 0;
}
#endif

static int _json_serialize(const struct json_value *v, char **out, char *end) {
    if (*out >= end) {
        return -1;
    }

    switch (v->type) {
        case JSON_STRING: {
            return _json_serialize_string(v, out, end);
        }

        case JSON_NUMBER: {
            return _json_serialize_number(v, out, end);
        }

        case JSON_BOOLEAN: {
            return _json_serialize_boolean(v, out, end);
        }

        case JSON_OBJECT: {
            return _json_serialize_object(v, out, end);
        }

#ifdef JSON_WITH_ARRAY
        case JSON_ARRAY: {
            return _json_serialize_array(v, out, end);
        }
#endif

        default: {
            return -1;
        }
    }
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

struct json_value *json_create_boolean(bool b) {
    struct json_value *v;

    v = malloc(sizeof(struct json_value));
    if (!v) {
        return NULL;
    }

    v->type = JSON_BOOLEAN;
    v->boolean = b;

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

#ifdef JSON_WITH_ARRAY
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
#endif

void json_free(struct json_value *v) {
    if (!v) {
        return;
    }

    switch (v->type) {        
        case JSON_STRING: {
            free(v->string);
            break;
        }

        case JSON_NUMBER: {
            break;
        }

        case JSON_BOOLEAN: {
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

#ifdef JSON_WITH_ARRAY
        case JSON_ARRAY: {
            for (int i = 0; i < v->array.count; i++) {
                json_free(v->array.items[i]);
            }

            free(v->array.items);
            break;
        }
#endif
    }

    free(v);
}


// Modify

static int _json_object_push(struct json_value *parent, char *key, struct json_value *child) {
    int count = parent->object.count;

    struct json_kv_pair *new_pairs = realloc(parent->object.pairs, sizeof(struct json_kv_pair) * (count + 1));
    if (!new_pairs) {
        return -1;
    }

    parent->object.pairs = new_pairs;
    parent->object.pairs[count].key = key;
    parent->object.pairs[count].value = child;
    ++parent->object.count;

    return 0;
}

int json_object_push(struct json_value *parent, const char *key, struct json_value *child) {
    char *copy = malloc(strlen(key) + 1);
    if (!copy) {
        return -1;
    }

    strcpy(copy, key);

    return _json_object_push(parent, copy, child);
}

#ifdef JSON_WITH_ARRAY
int json_array_push(struct json_value *parent, struct json_value *child) {
    int count = parent->array.count;

    struct json_value *new_items = realloc(parent->array.items, sizeof(struct json_value *) * (count + 1));
    if (!new_items) {
        return -1;
    }

    parent->array.items = new_items;
    parent->array.items[count] = child;
    ++parent->array.count;

    return 0;
}
#endif


// Access

const char *json_string_get(const struct json_value *v) {
    if (!v) {
        return NULL;
    }

    if (v->type != JSON_STRING) {
        return NULL;
    }

    return v->string;
}

const uint64_t *json_number_get(const struct json_value *v) {
    if (!v) {
        return NULL;
    }

    if (v->type != JSON_NUMBER) {
        return NULL;
    }

    return &v->number;
}

const bool *json_boolean_get(const struct json_value *v) {
    if (!v) {
        return NULL;
    }

    if (v->type != JSON_BOOLEAN) {
        return NULL;
    }

    return &v->boolean;
}

struct json_value *json_object_get(const struct json_value *v, const char *key) {
    if (!v) {
        return NULL;
    }

    if (v->type != JSON_OBJECT) {
        return NULL;
    }

    for (int i = 0; i < v->object.count; ++i) {
        if (!strcmp(v->object.pairs[i].key, key)) {
            return v->object.pairs[i].value;
        }
    }

    return NULL;
}

#ifdef JSON_WITH_ARRAY
struct json_value *json_array_get(struct json_value *v, int index) {
    if (v->type != JSON_ARRAY) {
        return NULL;
    }

    if (index >= v->array.count) {
        return NULL;
    }

    return v->array.items[index];
}
#endif
