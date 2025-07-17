#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include <libwebsockets.h>

#include <http/http.h>
#include <http/tasks/http_tasks.h>

static int http_callback(struct lws *socket, enum lws_callback_reasons reason, void *user, void *data, size_t length) {
    int ret = 0;
    struct http_state *state = (struct http_state *)lws_context_user(lws_get_context(socket));
    struct http_session *session = (struct http_session *)user;

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
                ret = lws_return_http_status(socket, HTTP_STATUS_METHOD_NOT_ALLOWED, "");

                ret = -EINVAL;

                break;
            }

            break;
        }

        case LWS_CALLBACK_HTTP_BODY: {
            short new_length = session->request.length + length;

            if (new_length > HTTP_MAX_PACKET_SIZE) {
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
            ret = http_handle_message(state, session);
            break;
        }

        case LWS_CALLBACK_HTTP_WRITEABLE: {
            ret = lws_write(socket, session->response.data, session->response.length, LWS_WRITE_HTTP_FINAL);
            if (ret != session->response.length) {
                return -1;
            }

            ret = lws_http_transaction_completed(socket);
            if (ret) {
                return ret;
            }

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
        .callback = http_callback,
        .per_session_data_size = sizeof(struct http_session),
        .rx_buffer_size = HTTP_MAX_PACKET_SIZE,
    },
    {NULL, NULL, 0, 0} // Terminator
};

int http_setup(struct http_state *state, struct http_config *config) {
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

int http_cleanup(struct http_state *state) {
    lws_context_destroy(state->context);

    return 0;
}
