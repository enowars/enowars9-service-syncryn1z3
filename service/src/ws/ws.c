#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include <libwebsockets.h>

#include <ws/ws.h>
#include <ws/tasks/ws_tasks.h>

static int ws_callback(struct lws *socket, enum lws_callback_reasons reason, void *user, void *data, size_t length) {
    struct ws_state *state = (struct ws_state *)lws_context_user(lws_get_context(socket));
    struct ws_message *session = (struct ws_message *)user;

    switch (reason) {
        case LWS_CALLBACK_RECEIVE: {
            if (lws_is_first_fragment(socket)) {
                session->socket = socket;
                
                if (lws_is_final_fragment(socket)) {
                    session->fragmented = false;
                    session->data = (char *)data;
                    session->length = length;
                    
                    return ws_handle_message(state, session);
                } else {
                    session->fragmented = true;
                    session->data = malloc(length);
                    if (!session->data) {
                        return -ENOMEM;
                    }

                    memcpy(session->data, data, length);
                    session->length = length;
                }
            } else {
                short new_length = session->length + length;

                if (!new_length > WS_MAX_PACKET_SIZE) {
                    return -EMSGSIZE;
                }

                session->data = realloc(session->data, new_length);
                if (!session->data) {
                    return -ENOMEM;
                }

                memcpy(session->data + session->length, data, length);
                session->length += length;

                if (lws_is_final_fragment(socket)) {
                    return ws_handle_message(state, session);
                }
            }

            break;
        }

        case LWS_CALLBACK_CLOSED: {
            if (session->fragmented) {
                free(session->data);
            }

            break;
        }
    }

    return 0;
}

static struct lws_protocols protocols[] = {
    {
        .name = "syncryn1z3",
        .callback = ws_callback,
        .per_session_data_size = sizeof(struct ws_message),
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
