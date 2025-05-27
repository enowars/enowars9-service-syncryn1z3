#include <string.h>

#include <libwebsockets.h>

#include <ws/ws.h>

static int ws_callback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_ESTABLISHED: {
            printf("Connection established\n");
            break;
        }

        case LWS_CALLBACK_RECEIVE: {
            printf("Received: %s\n", (char *)in);
            break;
        }

        default: {
            break;
        }
    }

    return 0;
}

static struct lws_protocols protocols[] = {
    {
        .name = "syncryn1z3",
        .callback = ws_callback,
        .per_session_data_size = 0,
        .rx_buffer_size = 0,
    },
    { NULL, NULL, 0, 0 } // Terminator
};

int ws_setup(struct ws_state *state, struct ws_config *config) {
    struct lws_context_creation_info info;
    struct lws_context *context;

    memset(&info, 0, sizeof(info));
    info.port = config->port;
    info.protocols = protocols;
    info.options |= LWS_SERVER_OPTION_LIBUV;
    info.foreign_loops = (void **)&config->loop;
    info.count_threads = 1;

    state->context = lws_create_context(&info);
    if (!state->context) {
        printf("lws_create_context failed\n");
        return -1;
    }

    return 0;
}

int ws_cleanup(struct ws_state *state) {
    lws_context_destroy(state->context);

    return 0;
}
