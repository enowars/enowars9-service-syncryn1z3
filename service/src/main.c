#include <string.h>
#include <stdio.h>

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

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    int ret;

    struct main_state state;

    // Line buffered output
    setvbuf(stdout, NULL, _IOLBF, 0);

    memset(&state, 0, sizeof(state));

    // Locally administered OUI range
    static const ptp_decoded_clock_id_t clock_id = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

    memcpy(state.config.ptp.clock_id, clock_id, sizeof(clock_id));
    state.config.ptp.clock_priority = 0;
    state.config.ptp.clock_quality.clock_class = PTP_CLOCK_CLASS_APPLICATION_SPECIFIC;
    state.config.ptp.clock_quality.clock_accuracy = PTP_CLOCK_ACCURACY_10_US;
    state.config.ptp.clock_quality.offset_scaled_log_variance = 0; // TODO: Fix

    state.config.ptp.port_db_filename = "/data/ports.db";

    state.config.socket.event_port = ptp_default_event_port;
    state.config.socket.general_port = ptp_default_general_port;
    state.config.socket.enqueue_callback = ptp_enqueue_message;
    state.config.socket.dequeue_callback = ptp_dequeue_message;
    state.config.socket.user_ptr = &state.ptp;

    printf("Starting PTP master\n");

    ret = ptp_setup(&state.ptp, &state.config.ptp);
    if (ret) {
        return -ret;
    }

    ret = socket_setup(&state.socket, &state.config.socket);
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
