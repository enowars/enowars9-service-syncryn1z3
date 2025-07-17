#pragma once

#include <stdint.h>

#include <uv.h>

#define HTTP_MAX_PACKET_SIZE 4096

struct lws_context;

struct http_config {
    struct db_state *db_state;
    uv_loop_t *loop;

    uint16_t port;
};

struct http_state {
    struct http_config *config;

    struct lws_context *context;
};

int http_setup(struct http_state *state, struct http_config *config);
int http_cleanup(struct http_state *state);
