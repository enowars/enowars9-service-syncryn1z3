#pragma once

#include <stdint.h>

#include <ptp/protocol/ptp_decoded.h>

struct sqlite3;

struct db_entry {
    struct ptp_decoded_port_id port_id;

    bool active;

    enum ptp_authentication_policy authentication_policy;
    char secret[PTP_PORT_SECRET_SIZE];
    
    char user_description[PTP_USER_DESCRIPTION_SIZE];
};

struct db_config {
    const char *filename;
};

struct db_state {
    struct sqlite3 *handle;

    struct db_entry *cache;
};

int db_setup(struct db_state *state, struct db_config *config);
int db_cleanup(struct db_state *state);

int db_get(struct db_state *state, struct db_entry **entry, struct ptp_decoded_port_id port_id);
int db_set(struct db_state *state, struct db_entry *entry);
