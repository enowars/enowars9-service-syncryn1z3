#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <ptp/ptp.h>
#include <ptp/ptp_defaults.h>
#include <socket/socket.h>
#include <util/signal.h>

struct main_config {
    struct ptp_config ptp;
    struct socket_config socket;
};

struct main_state {
    struct main_config config;

    struct ptp_state ptp;
    struct socket_state socket;
};

void usage(const char *program) {
    fprintf(stderr, "Usage: %s [-a ADDRESS] [-i INDEX]\n", program);
    exit(EXIT_FAILURE);
}

void parse_cli(int argc, char *argv[], struct main_config *config) {
    int opt;

    while ((opt = getopt(argc, argv, "a:i:")) != -1) {
        switch (opt) {
            case 'a': {
                const in_addr_t address = inet_addr(optarg);
                if (address == (in_addr_t)(-1)) {
                    fprintf(stderr, "Failed to parse address");
                    usage(argv[0]);
                }

                config->socket.server_address = address;
                break;
            }

            case 'i': {
                const int index = atoi(optarg);
                if (!index) {
                    fprintf(stderr, "Failed to parse index");
                    usage(argv[0]);
                }

                config->ptp.clock_id[7] = index;
                break;
            }

            default: {
                usage(argv[0]);
            }
        }
    }
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    int ret;

    struct main_state state;

    // Line buffered output
    setvbuf(stdout, NULL, _IOLBF, 0);

    memset(&state, 0, sizeof(state));

    // Locally administered OUI range
    static const ptp_decoded_clock_id_t clock_id = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    memcpy(state.config.ptp.clock_id, clock_id, sizeof(clock_id));
    state.config.ptp.clock_priority = 0;
    state.config.ptp.clock_quality.clock_class = PTP_CLOCK_CLASS_APPLICATION_SPECIFIC;
    state.config.ptp.clock_quality.clock_accuracy = PTP_CLOCK_ACCURACY_10_MS;
    state.config.ptp.clock_quality.offset_scaled_log_variance = 0; // TODO: Fix

    state.config.ptp.task_interval_s = 1;
    state.config.ptp.peer_expiration_time_s = 60;
    state.config.ptp.log_announce_interval = 1; // 2s
    state.config.ptp.log_sync_interval = 0; // 1s

    state.config.ptp.peer_db_filename = "/data/peers.db";
    state.config.ptp.port_db_filename = "/data/ports.db";

    state.config.socket.multicast_address = ptp_default_address;
    state.config.socket.event_port = ptp_default_event_port;
    state.config.socket.general_port = ptp_default_general_port;
    state.config.socket.enqueue_callback = ptp_enqueue_message;
    state.config.socket.dequeue_callback = ptp_dequeue_message;
    state.config.socket.user_ptr = &state.ptp;

    parse_cli(argc, argv, &state.config);

    printf("Starting PTP master\n");

    ret = ptp_setup(&state.ptp, &state.config.ptp);
    if (ret) {
        return -ret;
    }

    ret = socket_setup(&state.socket, &state.config.socket);
    if (ret) {
        return -ret;
    }

    ret = ptp_start(&state.ptp);
    if (ret) {
        return -ret;
    }

    ret = socket_start(&state.socket);
    if (ret) {
        return -ret;
    }

    util_wait_for_exit();

    printf("Shutting down...\n");

    ret = socket_stop(&state.socket);
    if (ret) {
        return -ret;
    }

    ret = ptp_stop(&state.ptp);
    if (ret) {
        return -ret;
    }

    ret = socket_cleanup(&state.socket);
    if (ret) {
        return -ret;
    }

    ret = ptp_cleanup(&state.ptp);
    if (ret) {
        return -ret;
    }

    return 0;
}
