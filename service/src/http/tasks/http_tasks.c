#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include <json.h>
#include <libwebsockets.h>

#include <db/db.h>
#include <ptp/protocol/ptp_constants.h>
#include <http/http.h>
#include <http/tasks/http_tasks.h>
#include <util/error.h>
#include <util/time.h>
#include <util/base64.h>

#define HTTP_MAX_PAGE_SIZE 16
#define HTTP_MAX_HEADER_SIZE 1028 

static int http_send_response(struct http_session *session, struct json_value *response_json) {
    int ret;

    char json_buffer[HTTP_MAX_PACKET_SIZE];

    ret = json_serialize(response_json, json_buffer, HTTP_MAX_PACKET_SIZE);
    if (ret) {
        fprintf(stderr, "Failed to serialize JSON response\n");
        return ret;
    }

    session->response.length = strnlen(json_buffer, HTTP_MAX_PACKET_SIZE);

    session->response.buffer = malloc(LWS_PRE + HTTP_MAX_HEADER_SIZE + session->response.length);
    if (!session->response.buffer) {
        return -ENOMEM;
    }

    session->response.data = ((char *)session->response.buffer) + LWS_PRE;
    uint8_t *head = session->response.data;
    uint8_t *end = session->response.data + HTTP_MAX_HEADER_SIZE - 1;

    ret = lws_add_http_common_headers(session->socket, HTTP_STATUS_OK, "application/json", session->response.length, &head, end);
    if (ret < 0) {
        return ret;
    }

    ret = lws_finalize_write_http_header(session->socket, session->response.data, &head, end);
    if (ret) {
        return ret;
    }

    memcpy(head, json_buffer, session->response.length);
    session->response.data = head;

    lws_callback_on_writable(session->socket);

    return 0;
}

static int http_send_error_va(struct http_session *session, int code, const char *format, va_list va_args) {
    int ret;
    char message[1024];

    ret = vsnprintf(message, sizeof(message), format, va_args);
    if (ret < 0) {
        return ret;
    }

    struct json_value *response_json = json_create_object();

    json_object_push(response_json, "error", json_create_string(message));
    json_object_push(response_json, "code", json_create_number(util_error_int(code)));

    ret = http_send_response(session, response_json);

    json_free(response_json);
    
    return ret;
}

static inline int http_send_error(struct http_session *session, int code, const char *format, ...) {
    va_list va_args;
    va_start(va_args, format);

    return http_send_error_va(session, code, format, va_args); 
}

static int http_handle_task_get_clocks(struct http_state *state, struct http_session *session, struct json_value *request_json) {   
    int ret;
    struct db_entry *entries[HTTP_MAX_PAGE_SIZE];

    struct json_value *length_json = json_object_get(request_json, "length");

    if (!json_number_get(length_json)) {
        return http_send_error(session, EINVAL, "Missing value");
    }

    const short length = *json_number_get(length_json) >= 1 ? (*json_number_get(length_json) <= HTTP_MAX_PAGE_SIZE ? *json_number_get(length_json) : HTTP_MAX_PAGE_SIZE) : 1;

    ret = db_get_recent(state->config->db_state, entries, length);
    if (ret) {
        return http_send_error(session, ret, "Failed to get clocks from database");
    }

    struct json_value *response_json = json_create_object();

    json_object_push(response_json, "task", json_create_string("get_clocks"));
    
    struct json_value *ports_json = json_create_object();

    for (int i = 0; i < length; ++i) {
        if (!entries[i]) {
            break;
        }

        struct json_value *port_json = json_create_object();
        char hex[17];

        snprintf(hex, sizeof(hex), "%lx", entries[i]->port_id.clock_id);
        json_object_push(port_json, "clockId", json_create_string(hex));

        snprintf(hex, sizeof(hex), "%hx", entries[i]->port_id.port);
        json_object_push(port_json, "port", json_create_string(hex));

        json_object_push(port_json, "time", json_create_number((util_get_time_ns() + entries[i]->offset) / 1000000000L));

        char index_string[3];
        snprintf(index_string, sizeof(index_string), "%d", i);

        json_object_push(ports_json, index_string, port_json);    
    }

    json_object_push(response_json, "ports", ports_json);  

    ret = http_send_response(session, response_json);

    json_free(response_json);
    
    return ret;
}

static int http_handle_task_inspect_clock(struct http_state *state, struct http_session *session, struct json_value *request_json) {   
    int ret;
    struct db_entry *entry;

    struct json_value *clock_id_json = json_object_get(request_json, "clockId");
    struct json_value *port_json = json_object_get(request_json, "port");
    struct json_value *secret_json = json_object_get(request_json, "secret");

    if (!json_string_get(clock_id_json) || !json_string_get(port_json) || !json_string_get(secret_json)) {
        return http_send_error(session, EINVAL, "Missing value");
    }

    struct ptp_decoded_port_id port_id;
    port_id.clock_id = strtoul(json_string_get(clock_id_json), NULL, 16);
    port_id.port = strtoul(json_string_get(port_json), NULL, 16);

    ret = db_get(state->config->db_state, &entry, port_id);
    if (ret) {
        return http_send_error(session, ret, "Failed to get clock from database");
    }

    if (!entry->visible) {
        return http_send_error(session, ret, "Invisible clock");
    }

    if (entry->authentication_policy != PTP_AUTHENTICATION_POLICY_NONE) {
        ret = strncmp(entry->secret, json_string_get(secret_json), DB_SECRET_SIZE);
        if (ret) {
            return http_send_error(session, ret, "Wrong secret");
        }
    }

    struct json_value *response_json = json_create_object();
    json_object_push(response_json, "task", json_create_string("inspect_clock"));

    char hex[17];

    snprintf(hex, sizeof(hex), "%lx", entry->port_id.clock_id);
    json_object_push(response_json, "clockId", json_create_string(hex));

    snprintf(hex, sizeof(hex), "%hx", entry->port_id.port);
    json_object_push(response_json, "port", json_create_string(hex));

    switch (entry->authentication_policy) {
        case PTP_AUTHENTICATION_POLICY_NONE: {
            json_object_push(response_json, "authenticationPolicy", json_create_string("none"));
            break;
        }

        case PTP_AUTHENTICATION_POLICY_PLAIN: {
            json_object_push(response_json, "authenticationPolicy", json_create_string("plain"));
            break;
        }

        case PTP_AUTHENTICATION_POLICY_HMAC_128: {
            json_object_push(response_json, "authenticationPolicy", json_create_string("hmac"));
            break;
        }
    }

    char user_description_base64[(((DB_USER_DESCRIPTION_SIZE + 2) / 3) * 4) + 1];
    ret = util_base64_encode(user_description_base64, entry->user_description, sizeof(user_description_base64), entry->user_description_length);
    if (ret < 0) {
        goto out;
    }

    json_object_push(response_json, "userDescription", json_create_string(user_description_base64));

    ret = http_send_response(session, response_json);

out:
    json_free(response_json);
    
    return ret;
}

static int http_handle_task_create_clock(struct http_state *state, struct http_session *session, struct json_value *request_json) {   
    int ret;
    struct db_entry *entries[HTTP_MAX_PAGE_SIZE];

    struct json_value *clock_id_json = json_object_get(request_json, "clockId");
    struct json_value *port_json = json_object_get(request_json, "port");
    struct json_value *offset_json = json_object_get(request_json, "offset");
    struct json_value *authentication_policy_json = json_object_get(request_json, "authenticationPolicy");
    struct json_value *visible_json = json_object_get(request_json, "visible");
    struct json_value *secret_json = json_object_get(request_json, "secret");
    struct json_value *user_description_json = json_object_get(request_json, "userDescription");

    if (!json_string_get(clock_id_json) || !json_string_get(port_json) || !json_number_get(offset_json) || !json_string_get(authentication_policy_json) || !json_boolean_get(visible_json) || !json_string_get(secret_json) || !json_string_get(user_description_json)) {
        return http_send_error(session, EINVAL, "Missing value");
    }

    struct db_entry entry;
    entry.port_id.clock_id = strtoul(json_string_get(clock_id_json), NULL, 16);
    entry.port_id.port = strtoul(json_string_get(port_json), NULL, 16);
    entry.offset = *json_number_get(offset_json) - util_get_time_ns();
    entry.visible = *json_boolean_get(visible_json);
    strncpy(entry.secret, json_string_get(secret_json), DB_SECRET_SIZE);

    ret = util_base64_decode(entry.user_description, json_string_get(user_description_json), DB_USER_DESCRIPTION_SIZE);
    if (ret < 0) {
        return http_send_error(session, ret, "Base64 decoding failed");
    }

    entry.user_description_length = ret;

    if (!strcmp(json_string_get(authentication_policy_json), "none")) {
        entry.authentication_policy = PTP_AUTHENTICATION_POLICY_NONE;
    } else if (!strcmp(json_string_get(authentication_policy_json), "plain")) {
        entry.authentication_policy = PTP_AUTHENTICATION_POLICY_PLAIN;
    } else if (!strcmp(json_string_get(authentication_policy_json), "hmac")) {
        entry.authentication_policy = PTP_AUTHENTICATION_POLICY_HMAC_128;
    } else {
        return http_send_error(session, EINVAL, "Invalid authentication policy");
    }

    ret = db_set(state->config->db_state, &entry);
    if (ret) {
        return http_send_error(session, ret, "Failed to create clock in database");
    }

    struct json_value *response_json = json_create_object();
    
    json_object_push(response_json, "task", json_create_string("create_clock"));

    ret = http_send_response(session, response_json);
    
    json_free(response_json);
    
    return ret;
}

static int http_handle_task(struct http_state *state, struct http_session *session, struct json_value *request_json) {   
    int ret;

    struct json_value *task_json = json_object_get(request_json, "task");
    
    if (!json_string_get(task_json)) {
        return http_send_error(session, EINVAL, "Missing task string");
    }

    if (!strcmp(json_string_get(task_json), "get_clocks")) {
        ret = http_handle_task_get_clocks(state, session, request_json);
    } else if (!strcmp(json_string_get(task_json), "inspect_clock")) {
        ret = http_handle_task_inspect_clock(state, session, request_json);
    } else if (!strcmp(json_string_get(task_json), "create_clock")) {
        ret = http_handle_task_create_clock(state, session, request_json);
    } else {
        return http_send_error(session, EINVAL, "Invalid task");
    }

    if (ret) {
        return http_send_error(session, util_error_int(ret), "General error");
    }

    return 0;
}

int http_handle_message(struct http_state *state, struct http_session *session) {   
    int ret;
    struct json_value *request_json;
    
    request_json = json_parse(session->request.data, session->request.length);
    if (!request_json) {
        return http_send_error(session, EINVAL, "JSON parse error");
    }

    ret = http_handle_task(state, session, request_json);

    json_free(request_json);

    return ret;
}
