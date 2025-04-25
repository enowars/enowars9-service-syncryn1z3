#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <arpa/inet.h>

#include <common/common_types.h>
#include <util/mempool.h>

struct socket_config {
    uint16_t port;

    int (*enqueue_callback)(void *user_ptr, struct common_message_info *info);
    int (*dequeue_callback)(void *user_ptr, struct common_message_info **info);

    void *user_ptr;
};

struct socket_state {
    struct socket_config *config;

    int fd;

    pthread_t thread;
    volatile bool exit_flag;

    struct sockaddr_in server_address;

    struct util_mempool mempool;
};

int socket_setup(struct socket_state *state);
int socket_cleanup(struct socket_state *state);

int socket_start(struct socket_state *state);
int socket_stop(struct socket_state *state);
