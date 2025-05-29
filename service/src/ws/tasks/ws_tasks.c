#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include <cjson/cJSON.h>
#include <libwebsockets.h>

#include <db/db.h>
#include <ptp/protocol/ptp_constants.h>
#include <ws/ws.h>
#include <ws/tasks/ws_tasks.h>
#include <util/error.h>

#define WS_MAX_PAGE_SIZE 16
#define WS_MAX_RESPONSE_SIZE 4096

static int ws_send_response(struct ws_message *request, cJSON *response_json) {
    int ret;

    void *response_buffer = ((char *)malloc(WS_MAX_RESPONSE_SIZE + LWS_PRE));
    char *response = ((char *)response_buffer) + LWS_PRE;

    if (!cJSON_PrintPreallocated(response_json, response, WS_MAX_RESPONSE_SIZE, false)) {
        fprintf(stderr, "Failed to serialize JSON response\n");
        free(response_buffer);

        return -1;
    }

    ret = lws_write(request->socket, (uint8_t *)response, strnlen(response, WS_MAX_RESPONSE_SIZE), LWS_WRITE_TEXT);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

static int ws_send_error_va(struct ws_message *request, int code, const char *format, va_list va_args) {
    int ret;
    char message[1024];

    ret = vsnprintf(message, sizeof(message), format, va_args);
    if (ret < 0) {
        return ret;
    }

    cJSON *response_json = cJSON_CreateObject();

    if (!cJSON_AddStringToObject(response_json, "error", message)) {
        ret = -1;
        goto out;
    }

    if (!cJSON_AddNumberToObject(response_json, "code", code)) {
        ret = -1;
        goto out;
    }

    ret = ws_send_response(request, response_json);

out:
    cJSON_Delete(response_json);
    
    return ret;
}

static inline int ws_send_error(struct ws_message *request, int code, const char *format, ...) {
    va_list va_args;
    va_start(va_args, format);

    return ws_send_error_va(request, code, format, va_args); 
}

int ws_handle_task_get_clocks(struct ws_state *state, struct ws_message *request, cJSON *request_json) {   
    int ret;
    struct db_entry *entries[WS_MAX_PAGE_SIZE];

    cJSON *length_json = cJSON_GetObjectItemCaseSensitive(request_json, "length");

    if (!cJSON_IsNumber(length_json)) {
        return ws_send_error(request, ret, "Missing value");
    }

    const short length = (length_json->valuedouble) >= 1 ? ((length_json->valuedouble) <= WS_MAX_PAGE_SIZE ? length_json->valuedouble : WS_MAX_PAGE_SIZE) : 1;

    ret = db_get_recent(state->config->db_state, entries, length);
    if (ret) {
        return ws_send_error(request, ret, "Failed to get clocks from database");
    }

    cJSON *response_json = cJSON_CreateObject();
    
    if (!cJSON_AddStringToObject(response_json, "task", "get_clocks")) {
        ret = -1;
        goto out;
    }

    cJSON *ports_json = cJSON_AddArrayToObject(response_json, "ports");
    if (!ports_json) {
        ret = -1;
        goto out;
    }

    for (int i = 0; i < length; ++i) {
        if (!entries[i]) {
            break;
        }

        cJSON *port_json = cJSON_CreateObject();
        char hex[17];

        snprintf(hex, sizeof(hex), "%lx", entries[i]->port_id.clock_id);
        if (!cJSON_AddStringToObject(port_json, "clockId", hex)) {
            cJSON_Delete(port_json);
            ret = -1;
            goto out;
        }

        snprintf(hex, sizeof(hex), "%hx", entries[i]->port_id.port);
        if (!cJSON_AddStringToObject(port_json, "port", hex)) {
            cJSON_Delete(port_json);
            ret = -1;
            goto out;
        }

        switch (entries[i]->authentication_policy) {
            case PTP_AUTHENTICATION_POLICY_PLAIN: {
                if (!cJSON_AddStringToObject(port_json, "authenticationPolicy", "plain")) {
                    cJSON_Delete(port_json);
                    ret = -1;
                    goto out;
                }

                break;
            }

            case PTP_AUTHENTICATION_POLICY_HMAC_128: {
                if (!cJSON_AddStringToObject(port_json, "authenticationPolicy", "hmac")) {
                    cJSON_Delete(port_json);
                    ret = -1;
                    goto out;
                }

                break;
            }
        }

        cJSON_AddItemToArray(ports_json, port_json);       
    }

    ret = ws_send_response(request, response_json);

out:
    cJSON_Delete(response_json);
    
    return ret;
}

int ws_handle_task_inspect_clock(struct ws_state *state, struct ws_message *request, cJSON *request_json) {   
    int ret;
    struct db_entry *entry;

    cJSON *clock_id_json = cJSON_GetObjectItemCaseSensitive(request_json, "clockId");
    cJSON *port_json = cJSON_GetObjectItemCaseSensitive(request_json, "port");
    cJSON *secret_json = cJSON_GetObjectItemCaseSensitive(request_json, "secret");

    if (!cJSON_IsString(clock_id_json) || !cJSON_IsString(port_json) || !cJSON_IsString(secret_json)) {
        return ws_send_error(request, EINVAL, "Missing value");
    }

    struct ptp_decoded_port_id port_id;
    port_id.clock_id = strtoul(clock_id_json->valuestring, NULL, 16);
    port_id.port = strtoul(port_json->valuestring, NULL, 16);

    ret = db_get(state->config->db_state, &entry, port_id);
    if (ret) {
        return ws_send_error(request, ret, "Failed to get clock from database");
    }

    if (!entry->visible) {
        return ws_send_error(request, ret, "Invisible clock");
    }

    ret = strncmp(entry->secret, secret_json->valuestring, DB_SECRET_SIZE);
    if (ret) {
        return ws_send_error(request, ret, "Wrong secret"); // Vuln: return value gets leaked
    }

    cJSON *response_json = cJSON_CreateObject();

    if (!cJSON_AddStringToObject(response_json, "task", "inspect_clock")) {
        ret = -1;
        goto out;
    }

    char hex[17];

    snprintf(hex, sizeof(hex), "%lx", entry->port_id.clock_id);
    if (!cJSON_AddStringToObject(response_json, "clockId", hex)) {
        ret = -1;
        goto out;
    }

    snprintf(hex, sizeof(hex), "%hx", entry->port_id.port);
    if (!cJSON_AddStringToObject(response_json, "port", hex)) {
        ret = -1;
        goto out;
    }

    switch (entry->authentication_policy) {
        case PTP_AUTHENTICATION_POLICY_PLAIN: {
            if (!cJSON_AddStringToObject(response_json, "authenticationPolicy", "plain")) {
                ret = -1;
                goto out;
            }

            break;
        }

        case PTP_AUTHENTICATION_POLICY_HMAC_128: {
            if (!cJSON_AddStringToObject(response_json, "authenticationPolicy", "hmac")) {
                ret = -1;
                goto out;
            }

            break;
        }
    }

    if (!cJSON_AddStringToObject(response_json, "userDescription", entry->user_description)) {
        ret = -1;
        goto out;
    }

    ret = ws_send_response(request, response_json);

out:
    cJSON_Delete(response_json);
    
    return ret;
}

int ws_handle_task_create_clock(struct ws_state *state, struct ws_message *request, cJSON *request_json) {   
    int ret;
    struct db_entry *entries[WS_MAX_PAGE_SIZE];

    cJSON *clock_id_json = cJSON_GetObjectItemCaseSensitive(request_json, "clockId");
    cJSON *port_json = cJSON_GetObjectItemCaseSensitive(request_json, "port");
    cJSON *authentication_policy_json = cJSON_GetObjectItemCaseSensitive(request_json, "authenticationPolicy");
    cJSON *visible_json = cJSON_GetObjectItemCaseSensitive(request_json, "visible");
    cJSON *secret_json = cJSON_GetObjectItemCaseSensitive(request_json, "secret");
    cJSON *user_description_json = cJSON_GetObjectItemCaseSensitive(request_json, "userDescription");

    if (!cJSON_IsString(clock_id_json) || !cJSON_IsString(port_json) || !cJSON_IsString(authentication_policy_json) || !cJSON_IsBool(visible_json) || !cJSON_IsString(secret_json) || !cJSON_IsString(user_description_json)) {
        return ws_send_error(request, EINVAL, "Missing value");
    }

    struct db_entry entry;
    entry.port_id.clock_id = strtoul(clock_id_json->valuestring, NULL, 16);
    entry.port_id.port = strtoul(port_json->valuestring, NULL, 16);
    entry.visible = cJSON_IsTrue(visible_json);
    strncpy(entry.secret, secret_json->valuestring, DB_SECRET_SIZE);
    strncpy(entry.user_description, user_description_json->valuestring, DB_USER_DESCRIPTION_SIZE);

    if (!strcmp(authentication_policy_json->valuestring, "plain")) {
        entry.authentication_policy = PTP_AUTHENTICATION_POLICY_PLAIN;
    } else if (!strcmp(authentication_policy_json->valuestring, "hmac")) {
        entry.authentication_policy = PTP_AUTHENTICATION_POLICY_HMAC_128;
    } else {
        return ws_send_error(request, EINVAL, "Invalid authentication policy");
    }

    ret = db_set(state->config->db_state, &entry);
    if (ret) {
        return ws_send_error(request, ret, "Failed to create clock in database");
    }

    cJSON *response_json = cJSON_CreateObject();
    
    if (!cJSON_AddStringToObject(response_json, "task", "create_clock")) {
        ret = -1;
        goto out;
    }

    ret = ws_send_response(request, response_json);
    
out:
    cJSON_Delete(response_json);
    
    return ret;
}

int ws_handle_task(struct ws_state *state, struct ws_message *request, cJSON *request_json) {   
    int ret;

    const cJSON *task_json = cJSON_GetObjectItemCaseSensitive(request_json, "task");
    
    if (!cJSON_IsString(task_json)) {
        return ws_send_error(request, EINVAL, "Missing task string");
    }

    if (!strcmp(task_json->valuestring, "get_clocks")) {
        ret = ws_handle_task_get_clocks(state, request, request_json);
    } else if (!strcmp(task_json->valuestring, "inspect_clock")) {
        ret = ws_handle_task_inspect_clock(state, request, request_json);
    } else if (!strcmp(task_json->valuestring, "create_clock")) {
        ret = ws_handle_task_create_clock(state, request, request_json);
    } else {
        return ws_send_error(request, EINVAL, "Invalid task");
    }

    if (ret) {
        return ws_send_error(request, util_error_int(ret), "General error");
    }

    return 0;
}

int ws_handle_message(struct ws_state *state, struct ws_message *request) {   
    int ret;
    cJSON *request_json;
    
    request_json = cJSON_ParseWithLength(request->data, request->length);
    if (!request_json) {
        const char *error_string = cJSON_GetErrorPtr();
        if (error_string) {
            fprintf(stderr, "JSON parse error: %s\n", error_string);
        }

        ret = -1;
        goto out;
    }

    ret = ws_handle_task(state, request, request_json);

out:
    cJSON_Delete(request_json);

    return ret;
}
