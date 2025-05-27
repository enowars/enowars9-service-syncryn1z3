#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <uv.h>

#include <common/common_types.h>
#include <util/mempool.h>

#define SOCKET_INSTANCE_NUM 2 

struct socket_config {
    uv_loop_t *loop;

    uint16_t event_port;
    uint16_t general_port;

    int (*enqueue_callback)(void *user_ptr, struct common_message_info *info);
    int (*dequeue_callback)(void *user_ptr, struct common_message_info **info);

    void *user_ptr;
};

struct socket_state {
    struct socket_config *config;

    struct socket_instance {
        struct socket_state *state;

        uv_poll_t handle;
        int fd;
        
        uint16_t port;
        enum common_port_type port_type;
    } instances[SOCKET_INSTANCE_NUM];

    pthread_t thread;
    volatile bool exit_flag;

    struct sockaddr_in address;

    struct util_mempool mempool;
};

int socket_setup(struct socket_state *state, struct socket_config *config);
int socket_cleanup(struct socket_state *state);
