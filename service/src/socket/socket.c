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

    ret = state->config->dequeue_callback(state->config->user_ptr, &info);
    if (ret) {
        return ret;
    }

    ret = sendto(state->fd, info->buffer.data, info->buffer.length, 0, (const struct sockaddr *)&info->address.address, info->address.length);
    if (ret < 0) {
        perror("Failed to send message");
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

    int on = 1;
    ret = setsockopt(state->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (ret) {
        perror("Failed to enable address reuse");
        close(state->fd);

        return ret; 
    }

    memset(&state->address, 0, sizeof(state->address));

    state->address.sin_family = AF_INET;
    state->address.sin_addr.s_addr = INADDR_ANY;
    state->address.sin_port = htobe16(state->config->server_port);

    ret = bind(state->fd, (const struct sockaddr *)&state->address, sizeof(state->address));
    if (ret) {
        perror("Bind failed");
        close(state->fd);

        return ret; 
    }

    struct ifaddrs *addresses;
    struct ifaddrs *address_iter;
    const char *interface_name;
    ret = getifaddrs(&addresses);
    if (ret) {
        perror("Failed to get addresses");
        close(state->fd);

        return ret; 
    }

    for (address_iter = addresses; address_iter != NULL; address_iter = address_iter->ifa_next) {
        if (address_iter->ifa_addr && AF_INET == address_iter->ifa_addr->sa_family) {
            if (((struct sockaddr_in*)address_iter->ifa_addr)->sin_addr.s_addr == state->config->server_address) {
                interface_name = address_iter->ifa_name;
            }
        }
    }

    if (setsockopt(state->fd, SOL_SOCKET, SO_BINDTODEVICE, interface_name, strlen(interface_name))) {
        perror("Failed to bind to device");
        close(state->fd);

        return ret; 
	}

    freeifaddrs(addresses);

    uint8_t ttl = 64;
    ret = setsockopt(state->fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    if (ret) {
        perror("Failed to set multicast TTL");
        close(state->fd);

        return ret; 
    }

    struct ip_mreqn multicast_request;
    multicast_request.imr_multiaddr.s_addr = state->config->multicast_address;
    multicast_request.imr_address.s_addr = state->config->server_address;
    multicast_request.imr_ifindex = 0;

    if (setsockopt(state->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &multicast_request, sizeof(multicast_request))) {
        perror("Failed to join multicast group");
        close(state->fd);

        return ret; 
    }

    int off = 0;
    ret = setsockopt(state->fd, IPPROTO_IP, IP_MULTICAST_LOOP, &off, sizeof(off));
    if (ret) {
        perror("Failed to disable multicast loop");
        close(state->fd);

        return ret; 
    }

    printf("UDP server listening on port %d...\n", state->config->server_port);

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
