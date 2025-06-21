#pragma once

#include <stdint.h>

#include <ptp/protocol/ptp_decoded.h>

struct sqlite3;

#define DB_SECRET_SIZE 64
#define DB_USER_DESCRIPTION_SIZE 1500

struct db_entry {
    enum ptp_authentication_policy authentication_policy;
    struct ptp_decoded_port_id port_id;

    int64_t offset;
    bool valid;
    bool visible;

    short user_description_length;
    uint8_t user_description[DB_USER_DESCRIPTION_SIZE];

    char secret[DB_SECRET_SIZE];
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
int db_get_recent(struct db_state *state, struct db_entry **entries, short length);
int db_set(struct db_state *state, struct db_entry *entry);
