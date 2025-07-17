#pragma once

#include <stdbool.h>

struct lws;
struct ws_state;

struct ws_session {
    struct lws *socket;

    struct {
        char *data;
        short length;
    } request;

    struct {
        char *buffer;
        char *data;
        short length;
    } response;
};

int ws_handle_message(struct ws_state *state, struct ws_session *session);
