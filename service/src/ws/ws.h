#pragma once

#include <stdint.h>

#include <uv.h>

struct lws_context;

struct ws_config {
    struct db_state *db_state;
    uv_loop_t *loop;

    uint16_t port;
};

struct ws_state {
    struct ws_config *config;

    struct lws_context *context;
};

int ws_setup(struct ws_state *state, struct ws_config *config);
int ws_cleanup(struct ws_state *state);
