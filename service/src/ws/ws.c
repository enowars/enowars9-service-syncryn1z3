#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include <libwebsockets.h>

#include <ws/ws.h>
#include <ws/tasks/ws_tasks.h>

static int ws_callback(struct lws *socket, enum lws_callback_reasons reason, void *user, void *data, size_t length) {
    int ret = 0;
    struct ws_state *state = (struct ws_state *)lws_context_user(lws_get_context(socket));
    struct ws_session *session = (struct ws_session *)user;

    switch (reason) {
        case LWS_CALLBACK_HTTP: {
            session->socket = socket;
            session->request.data = NULL;
            session->request.length = 0;
            session->response.buffer = NULL;
            session->response.data = NULL;
            session->response.length = 0;

            // Only allow POST requests
            if (!lws_hdr_total_length(socket, WSI_TOKEN_POST_URI)) {
                session->response.buffer = malloc(LWS_PRE + WS_MAX_PACKET_SIZE);
                if (!session->response.buffer) {
                    return -ENOMEM;
                }

                session->response.data = ((char *)session->response.buffer) + LWS_PRE;
                char *head = session->response.data;
                char *end = session->response.data + WS_MAX_PACKET_SIZE - 1;

                ret = lws_add_http_common_headers(socket, HTTP_STATUS_METHOD_NOT_ALLOWED, "application/json", LWS_ILLEGAL_HTTP_CONTENT_LEN, &head, head + WS_MAX_PACKET_SIZE - 1);
                if (ret < 0) {
                    break;
                }

                ret = lws_finalize_write_http_header(session->socket, session->response.data, &head, end);
                if (ret) {
                    return ret;
                }

                lws_callback_on_writable(socket);

                ret = -EINVAL;

                break;
            }

            break;
        }

        case LWS_CALLBACK_HTTP_BODY: {
            short new_length = session->request.length + length;

            if (!new_length > WS_MAX_PACKET_SIZE) {
                return -EMSGSIZE;
            }

            session->request.data = realloc(session->request.data, new_length);
            if (!session->request.data) {
                return -ENOMEM;
            }

            memcpy(session->request.data + session->request.length, data, length);
            session->request.length += length;
                
            break;
        }

        case LWS_CALLBACK_HTTP_BODY_COMPLETION: {
            ret = ws_handle_message(state, session);
            break;
        }

        case LWS_CALLBACK_HTTP_WRITEABLE: {
            ret = lws_write(socket, session->response.data, session->response.length, LWS_WRITE_HTTP_FINAL);
            break;
        }

        case LWS_CALLBACK_CLOSED_HTTP: {
            free(session->request.data);
            free(session->response.buffer);
            break;
        }

        default: {
            break;
        }
    }

    return ret;
}

static struct lws_protocols protocols[] = {
    {
        .name = "http",
        .callback = ws_callback,
        .per_session_data_size = sizeof(struct ws_session),
        .rx_buffer_size = WS_MAX_PACKET_SIZE,
    },
    {NULL, NULL, 0, 0} // Terminator
};

int ws_setup(struct ws_state *state, struct ws_config *config) {
    struct lws_context_creation_info info;
    struct lws_context *context;

    state->config = config;

    memset(&info, 0, sizeof(info));
    info.port = state->config->port;
    info.protocols = protocols;
    info.user = state;
    info.options |= LWS_SERVER_OPTION_LIBUV;
    info.options |= LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;
    info.foreign_loops = (void **)&state->config->loop;
    info.count_threads = 1; 

    state->context = lws_create_context(&info);
    if (!state->context) {
        return -1;
    }

    return 0;
}

int ws_cleanup(struct ws_state *state) {
    lws_context_destroy(state->context);

    return 0;
}
