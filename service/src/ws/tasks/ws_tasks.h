#pragma once

#include <stdbool.h>

struct lws;
struct ws_state;

struct ws_message {
    struct lws *socket;

    char *data;
    short length;
    bool fragmented;
};

int ws_handle_message(struct ws_state *state, struct ws_message *request);
