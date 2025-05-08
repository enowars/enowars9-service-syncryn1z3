#pragma once

#include <stdint.h>
#include <arpa/inet.h>

#include <ptp/ptp_decoded.h>

struct sqlite3;

enum ptp_peer_subscription {
    PTP_PEER_SUBSCRIPTION_ANNOUNCE = (1 << 0),
    PTP_PEER_SUBSCRIPTION_SYNC = (1 << 1),
};

struct ptp_peer {
    struct ptp_decoded_port_id port_id;
    struct sockaddr_in address;
    
    enum ptp_peer_subscription subscriptions;
    uint64_t expiration;
};

struct ptp_peer_db {
    struct sqlite3 *handle;
};

int ptp_peer_db_setup(struct ptp_peer_db *db, const char *filename);
int ptp_peer_db_cleanup(struct ptp_peer_db *db);

int ptp_peer_db_add(struct ptp_peer_db *db, struct ptp_peer *peer);
int ptp_peer_db_remove(struct ptp_peer_db *db, struct ptp_peer *peer);
