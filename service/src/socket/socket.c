#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <endian.h>
#include <arpa/inet.h>

#include <socket/socket.h>

#define BUFFER_SIZE 2040
#define MEMPOOL_SIZE 8

static int receive_message(struct socket_state *state) {
    int ret;
    
    uint8_t *buffer = util_mempool_get(&state->mempool);

    if (!buffer) {
        return -1;
    }
    
    state->client.address_length = sizeof(state->client.address);

    ssize_t length = recvfrom(state->fd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&state->client.address, &state->client.address_length);
    if (length < 0) {
        perror("recvfrom failed");
        return -1;
    }

    printf("recvfrom message\n");

    if (state->config->enqueue_callback) {
        ret = state->config->enqueue_callback(state->config->user_ptr, buffer, length);
        if (ret) {
            return ret;
        }
    }

    return 0;
}

static void *thread_worker(void *arg) {
    struct socket_state *state = (struct socket_state *)arg;
    
    while (!state->exit_flag) {
        receive_message(state);
    }

    return NULL;
}

int socket_setup(struct socket_state *state) {
    int ret;
    
    state->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (state->fd < 0) {
        perror("Socket creation failed");

        return -1;
    }

    memset(&state->server.address, 0, sizeof(state->server.address));

    state->server.address.sin_family = AF_INET;
    state->server.address.sin_addr.s_addr = INADDR_ANY;
    state->server.address.sin_port = htobe16(state->config->port);

    ret = bind(state->fd, (const struct sockaddr *)&state->server.address, sizeof(state->server.address));
    if (ret) {
        perror("Bind failed");
        close(state->fd);

        return ret; 
    }

    printf("UDP server listening on port %d...\n", state->config->port);

    ret = util_mempool_setup(&state->mempool, BUFFER_SIZE, MEMPOOL_SIZE);
    if (ret) {
        return ret; 
    }

    return 0;
}

int socket_cleanup(struct socket_state *state) {
    int ret;

    ret = close(state->fd);
    if (ret) {
        return ret;
    }

    ret = util_mempool_cleanup(&state->mempool);
    if (ret) {
        return ret;
    }

    return 0;
}

int socket_start(struct socket_state *state) {
    int ret;

    state->exit_flag = false;

    ret = pthread_create(&state->thread, NULL, thread_worker, (void *)state);
    if (ret) {
        return ret;
    }

    return 0;
}

int socket_stop(struct socket_state *state) {
    int ret;

    state->exit_flag = true;

    ret = pthread_join(state->thread, NULL);
    if (ret) {
        return ret;
    }

    return 0;
}

