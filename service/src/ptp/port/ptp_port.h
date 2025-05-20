#pragma once

#include <stdint.h>

#include <ptp/protocol/ptp_decoded.h>

struct sqlite3;

struct ptp_port_entry {
    struct ptp_decoded_port_id port_id;

    bool active;

    enum ptp_authentication_policy authentication_policy;
    char secret[PTP_PORT_SECRET_SIZE];
    
    char user_description[PTP_USER_DESCRIPTION_SIZE];
};

struct ptp_port_db {
    struct sqlite3 *handle;

    struct ptp_port_entry *cache;
};

int ptp_port_db_setup(struct ptp_port_db *db, const char *filename);
int ptp_port_db_cleanup(struct ptp_port_db *db);

int ptp_port_db_get(struct ptp_port_db *db, struct ptp_port_entry **entry, struct ptp_decoded_port_id port_id);
int ptp_port_db_set(struct ptp_port_db *db, struct ptp_port_entry *entry);
