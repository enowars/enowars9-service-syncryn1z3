#include <string.h>
#include <stdio.h>

#include <uv.h>

#include <ptp/ptp.h>
#include <ptp/ptp_defaults.h>
#include <socket/socket.h>
#include <ws/ws.h>

struct main_config {
    struct ptp_config ptp;
    struct socket_config socket;
    struct ws_config ws;
};

struct main_state {
    struct main_config config;

    struct ptp_state ptp;
    struct socket_state socket;
    struct ws_state ws;

    uv_loop_t *loop;
};

static void handle_signal(uv_signal_t *handle, int signum) {
    uv_stop(handle->loop);
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    int ret;

    struct main_state state;
    uv_signal_t signal;

    // Line buffered output
    setvbuf(stdout, NULL, _IOLBF, 0);

    memset(&state, 0, sizeof(state));

    state.loop = uv_default_loop();

    state.config.ptp.clock_priority = 0;
    state.config.ptp.clock_quality.clock_class = PTP_CLOCK_CLASS_APPLICATION_SPECIFIC;
    state.config.ptp.clock_quality.clock_accuracy = PTP_CLOCK_ACCURACY_10_US;
    state.config.ptp.clock_quality.offset_scaled_log_variance = 0; // TODO: Fix

    state.config.ptp.port_db_filename = "/data/ports.db";

    state.config.socket.loop = state.loop;
    state.config.socket.event_port = ptp_default_event_port;
    state.config.socket.general_port = ptp_default_general_port;
    state.config.socket.enqueue_callback = ptp_enqueue_message;
    state.config.socket.dequeue_callback = ptp_dequeue_message;
    state.config.socket.user_ptr = &state.ptp;

    state.config.ws.loop = state.loop;
    state.config.ws.port = 8080;

    printf("Starting PTP master\n");

    ret = ptp_setup(&state.ptp, &state.config.ptp);
    if (ret) {
        return -ret;
    }

    ret = socket_setup(&state.socket, &state.config.socket);
    if (ret) {
        return -ret;
    }

    ret = ws_setup(&state.ws, &state.config.ws);
    if (ret) {
        return -ret;
    }

    uv_signal_init(state.loop, &signal);
    uv_signal_start(&signal, handle_signal, SIGTERM);

    uv_run(state.loop, UV_RUN_DEFAULT);

    printf("Shutting down...\n");

    ret = ws_cleanup(&state.ws);
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

    ret = uv_loop_close(state.loop);
    if (ret) {
        return -ret;
    }

    return 0;
}
