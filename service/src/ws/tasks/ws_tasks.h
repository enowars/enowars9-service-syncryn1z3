#pragma once

struct lws;
struct ws_state;

struct ws_message {
    struct lws *socket;

    char *data;
    short length;
};

int ws_handle_message(struct ws_state *state, struct ws_message *request);
