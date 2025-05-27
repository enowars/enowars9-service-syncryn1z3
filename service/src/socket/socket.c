#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <endian.h>
#include <errno.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

#include <socket/socket.h>
#include <common/common_types.h>
#include <util/error.h>

static int send_message(struct socket_state *state) {
    int ret;
    
    struct common_message_info *info;
    struct socket_instance *instance;

    ret = state->config->dequeue_callback(state->config->user_ptr, &info);
    if (ret) {
        if (-ret != ENODATA) {
            util_error(ret, "Failed to dequeue message");
        }

        return ret;
    }

    if (info->port_type >= SOCKET_INSTANCE_NUM) {
        ret = -EINVAL;
        goto out;
    }

    if (info->buffer.length <= 0) {
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

static void socket_poll(uv_poll_t* handle, int status, int events) {
    int ret;
    struct socket_instance *instance = (struct socket_instance *)handle->data;

    if (!(events & UV_READABLE)) {
        return;
    }

    receive_message(instance->state, instance);

    do {
        ret = send_message(instance->state);
    } while (!ret);
}

static int socket_setup_port(struct socket_state *state, struct socket_instance *instance) {
    int ret;

    instance->state = state;

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

    ret = uv_poll_init(state->config->loop, &instance->handle, instance->fd);
    if (ret) {
        util_error(ret, "Failed to initialize uv poll handle");
    }

    instance->handle.data = instance;

    ret = uv_poll_start(&instance->handle, UV_READABLE, socket_poll);
    if (ret) {
        util_error(ret, "Failed to start uv poll");
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
