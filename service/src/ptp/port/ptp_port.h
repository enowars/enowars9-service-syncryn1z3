#pragma once

#include <stdint.h>

#include <ptp/protocol/ptp_decoded.h>

struct sqlite3;

struct ptp_port_entry {
    uint16_t port;

    bool active;

    enum ptp_authentication_policy authentication_policy;
    char secret[PTP_PORT_SECRET_SIZE];
    
    char user_description[PTP_USER_DESCRIPTION_SIZE];
};

struct ptp_port_db {
    struct sqlite3 *handle;

    // TODO: add cache
};

int ptp_port_db_setup(struct ptp_port_db *db, const char *filename);
int ptp_port_db_cleanup(struct ptp_port_db *db);

int ptp_port_db_get(struct ptp_port_db *db, struct ptp_port_entry *entry);
int ptp_port_db_set(struct ptp_port_db *db, struct ptp_port_entry *entry);
