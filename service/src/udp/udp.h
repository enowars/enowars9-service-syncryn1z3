#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <uv.h>

#include <common/common_types.h>
#include <util/mempool.h>

#define UDP_INSTANCE_NUM 2 

struct udp_config {
    uv_loop_t *loop;

    uint16_t event_port;
    uint16_t general_port;

    int (*enqueue_callback)(void *user_ptr, struct common_message_info *info);
    int (*dequeue_callback)(void *user_ptr, struct common_message_info **info);

    void *user_ptr;
};

struct udp_state {
    struct udp_config *config;

    struct udp_instance {
        struct udp_state *state;

        uv_poll_t handle;
        int fd;
        
        uint16_t port;
        enum common_port_type port_type;
    } instances[UDP_INSTANCE_NUM];

    pthread_t thread;
    volatile bool exit_flag;

    struct sockaddr_in address;

    struct util_mempool mempool;
};

int udp_setup(struct udp_state *state, struct udp_config *config);
int udp_cleanup(struct udp_state *state);
