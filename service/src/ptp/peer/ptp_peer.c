#include <stdio.h>

#include <sqlite3.h>

#include <ptp/peer/ptp_peer.h>

int ptp_peer_db_setup(struct ptp_peer_db *db, const char *filename) {
    int ret;
    char *error_message;

    ret = sqlite3_open(filename, &db->handle);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "Failed to open database: %s\n", sqlite3_errmsg(db->handle));
        return -1;
    }

    const char *query =
        "CREATE TABLE IF NOT EXISTS\n"
        "peers(port_id BLOB PRIMARY KEY, address BLOB UNIQUE, subscriptions INTEGER, expiration INTEGER);\n";

    ret = sqlite3_exec(db->handle, query, 0, 0, &error_message);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", error_message);
        sqlite3_free(error_message);
        return -1;
    }

    return 0;
}

int ptp_peer_db_cleanup(struct ptp_peer_db *db) {
    // TODO: Fix logical time reset
    sqlite3_close(db->handle);

    return 0;
}

int ptp_peer_db_update_peer(struct ptp_peer_db *db, struct ptp_peer *peer) {
    int ret;
    char *error_message;
    sqlite3_stmt *statement;

    const char *query =
        "INSERT\n"
        "INTO peers(port_id, address, subscriptions, expiration)\n"
        "VALUES (?, ?, ?, ?)\n"
        "ON CONFLICT(address)\n"
        "DO UPDATE SET port_id=excluded.port_id, subscriptions=subscriptions|excluded.subscriptions, expiration=excluded.expiration;";

    ret = sqlite3_prepare_v2(db->handle, query, -1, &statement, 0);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->handle));
        return -1;
    }

    sqlite3_bind_blob(statement, 1, &peer->port_id, sizeof(peer->port_id), NULL);
    sqlite3_bind_blob(statement, 2, &peer->address, sizeof(peer->address), NULL);
    sqlite3_bind_int(statement, 3, peer->subscriptions);
    sqlite3_bind_int64(statement, 4, peer->expiration);

    ret = sqlite3_step(statement);
    if (ret != SQLITE_DONE) {
        fprintf(stderr, "Execution failed: %s\n", sqlite3_errmsg(db->handle));
        ret = -1;
        goto out;
    }

    ret = 0;

out:
    sqlite3_finalize(statement);

    return ret;
}

int ptp_peer_db_remove(struct ptp_peer_db *db, struct ptp_peer *peer) {
    return 0;
}
