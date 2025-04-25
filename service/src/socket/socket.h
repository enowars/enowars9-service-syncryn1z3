#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <arpa/inet.h>

#include <util/mempool.h>

struct socket_config {
    uint16_t port;

    int (*enqueue_callback)(void *user_ptr, uint8_t *buffer, size_t length);
    int (*dequeue_callback)(void *user_ptr, uint8_t **buffer, size_t *length);

    void *user_ptr;
};

struct socket_state {
    struct socket_config *config;

    int fd;

    pthread_t thread;
    volatile bool exit_flag;

    struct {
        struct sockaddr_in address;
    } server;

    struct {
        struct sockaddr_in address;
        socklen_t address_length;
    } client;

    struct util_mempool mempool;
};

int socket_setup(struct socket_state *state);
int socket_cleanup(struct socket_state *state);

int socket_start(struct socket_state *state);
int socket_stop(struct socket_state *state);
