#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <endian.h>
#include <errno.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>
#include <arpa/inet.h>

#include <socket/socket.h>
#include <common/common_types.h>
#include <util/signal.h>

static int send_message(struct socket_state *state) {
    int ret;
    
    struct common_message_info *info;

    ret = state->config->dequeue_callback(state->config->user_ptr, &info);
    if (ret) {
        return ret;
    }

    ret = sendto(state->fd, info->buffer.data, info->buffer.length, 0, (const struct sockaddr *)&info->address.address, info->address.length);
    if (ret < 0) {
        goto out;
    }

    ret = 0;

out:
    util_mempool_put(info);

    return ret;;
}

static int receive_message(struct socket_state *state) {
    int ret;
    
    struct common_message_info *info = util_mempool_get(&state->mempool);

    if (!info) {
        return -ENOMEM;
    }
    
    info->address.length = sizeof(info->address.address);

    info->buffer.length = recvfrom(state->fd, info->buffer.data, COMMON_BUFFER_SIZE, 0, (struct sockaddr *)&info->address.address, &info->address.length);
    if (info->buffer.length < 0) {
        perror("recvfrom failed");
        return -1;
    }

    if (state->config->enqueue_callback) {
        ret = state->config->enqueue_callback(state->config->user_ptr, info);
        if (ret) {
            return ret;
        }
    }

    return 0;
}

static void *thread_worker(void *arg) {
    int ret;

    struct socket_state *state = (struct socket_state *)arg;

    int epoll_fd;

    struct epoll_event event;

    util_block_signals();

    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create1 failed");
        exit(EXIT_FAILURE);
    }

    event.events = EPOLLIN;
    event.data.fd = state->fd;

    ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, state->fd, &event);
    if (ret) {
        perror("epoll_ctl for socket fd failed");
        exit(EXIT_FAILURE);
    }

    while (!state->exit_flag) {
        ret = epoll_wait(epoll_fd, &event, 1, 10);
        if (ret < 0) {
            perror("epoll_wait failed");
            continue;
        }

        const int event_count = ret;

        if (event_count > 0) {
            receive_message(state);
        }

        send_message(state);
    }

    ret = close(epoll_fd);
    if (ret) {
        perror("Failed to close epoll fd");
    }

    return NULL;
}

int socket_setup(struct socket_state *state, struct socket_config *config) {
    int ret;

    memset(state, 0, sizeof(*state));
    state->config = config;
    
    state->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (state->fd < 0) {
        perror("Socket creation failed");

        return -1;
    }

    memset(&state->server_address, 0, sizeof(state->server_address));

    state->server_address.sin_family = AF_INET;
    state->server_address.sin_addr.s_addr = INADDR_ANY;
    state->server_address.sin_port = htobe16(state->config->port);

    ret = bind(state->fd, (const struct sockaddr *)&state->server_address, sizeof(state->server_address));
    if (ret) {
        perror("Bind failed");
        close(state->fd);

        return ret; 
    }

    uint8_t ttl = 64;
    ret = setsockopt(state->fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    if (ret) {
        perror("setsockopt failed");
        close(state->fd);

        return ret; 
    }

    printf("UDP server listening on port %d...\n", state->config->port);

    ret = util_mempool_setup(&state->mempool, sizeof(struct common_message_info), COMMON_MEMPOOL_SIZE);
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
        perror("pthread_create failed");
        return ret;
    }

    return 0;
}

int socket_stop(struct socket_state *state) {
    int ret;

    state->exit_flag = true;

    ret = pthread_join(state->thread, NULL);
    if (ret) {
        perror("pthread_join failed");
        return ret;
    }

    return 0;
}
