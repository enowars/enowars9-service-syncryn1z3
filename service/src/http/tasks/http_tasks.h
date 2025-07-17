#pragma once

#include <stdbool.h>

struct lws;
struct http_state;

struct http_session {
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

int http_handle_message(struct http_state *state, struct http_session *session);
