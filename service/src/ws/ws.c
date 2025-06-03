#include <stdint.h>
#include <string.h>

#include <libwebsockets.h>

#include <ws/ws.h>
#include <ws/tasks/ws_tasks.h>

static int ws_callback(struct lws *socket, enum lws_callback_reasons reason, void *user, void *data, size_t length) {
    if (reason != LWS_CALLBACK_RECEIVE) {
        return 0;
    }

    struct ws_state *state = (struct ws_state *)lws_context_user(lws_get_context(socket));

    struct ws_message request;
    request.socket = socket;
    request.data = (char *)data;
    request.length = length;
    
    return ws_handle_message(state, &request);
}

static struct lws_protocols protocols[] = {
    {
        .name = "syncryn1z3",
        .callback = ws_callback,
        .per_session_data_size = 0,
        .rx_buffer_size = 0,
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
