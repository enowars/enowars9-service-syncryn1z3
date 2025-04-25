#pragma once

#include <ptp/ptp.h>

int ptp_run_acyclic_tasks(struct ptp_state *state);
int ptp_run_cyclic_tasks(struct ptp_state *state);
