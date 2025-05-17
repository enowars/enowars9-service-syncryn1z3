#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <endian.h>
#include <errno.h>
#include <ifaddrs.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>
#include <arpa/inet.h>

#include <socket/socket.h>
#include <common/common_types.h>
#include <util/signal.h>

static int send_message(struct socket_state *state) {
    int ret;
    
    struct common_message_info *info;
    struct socket_instance *instance;

    ret = state->config->dequeue_callback(state->config->user_ptr, &info);
    if (ret) {
        return ret;
    }

    if (info->port_type >= SOCKET_INSTANCE_NUM) {
        ret = -EINVAL;
        goto out;
    }

    instance = &state->instances[info->port_type];

    ret = sendto(instance->fd, info->buffer.data, info->buffer.length, 0, (const struct sockaddr *)&info->address.address, info->address.length);
    if (ret < 0) {
        perror("Failed to send message");
        goto out;
    }

    ret = 0;

out:
    util_mempool_put(info);

    return ret;
}

static int receive_message(struct socket_state *state, struct socket_instance *instance) {
    int ret;
    
    struct common_message_info *info = util_mempool_get(&state->mempool);

    if (!info) {
        return -ENOMEM;
    }
    
    info->address.length = sizeof(info->address.address);
    info->port_type = instance->port_type;

    info->buffer.length = recvfrom(instance->fd, info->buffer.data, COMMON_BUFFER_SIZE, 0, (struct sockaddr *)&info->address.address, &info->address.length);
    if (info->buffer.length < 0) {
        perror("Failed to receive message");
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

    for (int i = 0; i < SOCKET_INSTANCE_NUM; ++i) {
        event.events = EPOLLIN;
        event.data.ptr = &state->instances[i];

        ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, state->instances[i].fd, &event);
        if (ret) {
            perror("epoll_ctl for socket fd failed");
            exit(EXIT_FAILURE);
        }
    }

    while (!state->exit_flag) {
        ret = epoll_wait(epoll_fd, &event, 1, 10);
        if (ret < 0) {
            perror("epoll_wait failed");
            continue;
        }

        const int event_count = ret;

        if (event_count > 0) {
            receive_message(state, event.data.ptr);
        }

        do {
            ret = send_message(state);
        } while (!ret);
    }

    ret = close(epoll_fd);
    if (ret) {
        perror("Failed to close epoll fd");
    }

    return NULL;
}

static int socket_setup_port(struct socket_state *state, struct socket_instance *instance) {
    int ret;

    instance->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (instance->fd < 0) {
        perror("Socket creation failed");

        return -1;
    }

    int on = 1;
    ret = setsockopt(instance->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (ret) {
        perror("Failed to enable address reuse");
        goto out;
    }

    memset(&state->address, 0, sizeof(state->address));

    state->address.sin_family = AF_INET;
    state->address.sin_addr.s_addr = INADDR_ANY;
    state->address.sin_port = htobe16(instance->port);

    ret = bind(instance->fd, (const struct sockaddr *)&state->address, sizeof(state->address));
    if (ret) {
        perror("Bind failed");
        goto out; 
    }

    printf("UDP server listening on port %d...\n", instance->port);

    ret = util_mempool_setup(&state->mempool, sizeof(struct common_message_info), COMMON_MEMPOOL_SIZE);
    if (ret) {
        goto out;
    }

    return 0;

out:
    close(instance->fd);

    return ret;
}

int socket_setup(struct socket_state *state, struct socket_config *config) {
    int ret;

    memset(state, 0, sizeof(*state));
    state->config = config;

    state->instances[COMMON_PORT_TYPE_EVENT].port = state->config->event_port;
    state->instances[COMMON_PORT_TYPE_EVENT].port_type = COMMON_PORT_TYPE_EVENT;
    ret = socket_setup_port(state, &state->instances[COMMON_PORT_TYPE_EVENT]);
    if (ret) {
        return ret;
    }

    state->instances[COMMON_PORT_TYPE_GENERAL].port = state->config->general_port;
    state->instances[COMMON_PORT_TYPE_GENERAL].port_type = COMMON_PORT_TYPE_GENERAL;
    ret = socket_setup_port(state, &state->instances[COMMON_PORT_TYPE_GENERAL]);
    if (ret) {
        return ret;
    }

    return 0;
}

int socket_cleanup(struct socket_state *state) {
    int ret;

    for (int i = 0; i < SOCKET_INSTANCE_NUM; ++i) {
        ret = close(state->instances[i].fd);
        if (ret) {
            return ret;
        }
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
