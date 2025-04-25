#include <stdio.h>

#include <ptp/ptp.h>
#include <ptp/ptp_parse.h>
#include <ptp/ptp_protocol.h>
#include <util/time.h>
#include <util/mempool.h>

#define RING_SIZE 8
#define MEMPOOL_SIZE 8

struct ptp_message_info {
    uint8_t *buffer;
    int length;

    struct ptp_parsed_message message;

    uint64_t receive_timestamp;
    uint64_t send_timestamp;
};

static int ptp_handle_message(struct ptp_state *state) {   
    int ret;
    struct ptp_message_info *info;

    info = util_ring_get(&state->ring);
    if (!info) {
        return -1;
    }

    printf("Received message\n");

    ret = ptp_parse_message(&info->message, info->buffer, info->length);
    if (ret) {
        goto out;
    }

    return 0;

out:
    util_mempool_put(info->buffer);
    util_mempool_put(info);

    return ret;
}

static void *thread_worker(void *arg) {
    struct ptp_state *state = (struct ptp_state *)arg;
    
    while (!state->exit_flag) {
        ptp_handle_message(state);
    }

    return NULL;
}

int ptp_setup(struct ptp_state *state) {
    int ret;

    ret = util_ring_setup(&state->ring, RING_SIZE);
    if (ret) {
        return ret;
    }

    ret = util_mempool_setup(&state->receive_mempool, sizeof(struct ptp_message_info), MEMPOOL_SIZE);
    if (ret) {
        return ret; 
    }

    return 0;
}
    
int ptp_cleanup(struct ptp_state *state) {
    int ret;

    ret = util_ring_cleanup(&state->ring);
    if (ret) {
        return ret;
    }

    ret = util_mempool_cleanup(&state->receive_mempool);
    if (ret) {
        return ret;
    }

    return 0;
}

int ptp_start(struct ptp_state *state) {
    int ret;

    state->exit_flag = false;

    ret = pthread_create(&state->thread, NULL, thread_worker, (void *)state);
    if (ret) {
        return ret;
    }

    return 0;
}

int ptp_stop(struct ptp_state *state) {
    int ret;

    state->exit_flag = true;

    ret = pthread_join(state->thread, NULL);
    if (ret) {
        return ret;
    }

    return 0;
}

int ptp_enqueue_message(void *user_ptr, uint8_t *buffer, size_t length) {
    int ret;
    struct ptp_state *state = (struct ptp_state *)user_ptr;

    struct ptp_message_info *info = util_mempool_get(&state->receive_mempool);

    if (!info) {
        ret = -1;
        goto out;
        
    }

    info->receive_timestamp = util_get_time();
    info->buffer = buffer;
    info->length = length;

    ret = util_ring_put(&state->ring, info);
    if (ret) {
        goto out;
    }

    return 0;

out:
    util_mempool_put(buffer);
    return ret;
}

int ptp_dequeue_message(void *user_ptr, uint8_t **buffer, size_t *length) {
    return 0;
}
