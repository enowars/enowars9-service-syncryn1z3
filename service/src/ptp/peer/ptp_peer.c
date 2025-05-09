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

    const char *create_query =
        "CREATE TABLE IF NOT EXISTS\n"
        "peers(port_id BLOB PRIMARY KEY, address BLOB UNIQUE, subscriptions INTEGER, expiration INTEGER);\n";

    ret = sqlite3_exec(db->handle, create_query, 0, 0, &error_message);
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

int ptp_peer_db_add_subscription(struct ptp_peer_db *db, struct ptp_peer *peer) {
    int ret;
    char *error_message;
    sqlite3_stmt *statement;

    const char *insert_query =
        "INSERT INTO peers(port_id, address, subscriptions, expiration)\n"
        "VALUES (?, ?, ?, ?)\n"
        "ON CONFLICT(address)\n"
        "DO UPDATE SET port_id=excluded.port_id, subscriptions=subscriptions|excluded.subscriptions, expiration=excluded.expiration;";

    ret = sqlite3_prepare_v2(db->handle, insert_query, -1, &statement, 0);
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

int ptp_peer_db_remove_subscription(struct ptp_peer_db *db, struct ptp_peer *peer) {
    int ret;
    char *error_message;
    sqlite3_stmt *statement;

    const char *update_query =
        "UPDATE peers\n"
        "SET subscriptions=subscriptions&(?)\n"
        "WHERE (port_id==? AND address==?);\n";

    ret = sqlite3_prepare_v2(db->handle, update_query, -1, &statement, 0);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->handle));
        return -1;
    }

    sqlite3_bind_int(statement, 1, ~peer->subscriptions & PTP_TLV_UNICAST_FLAG_MASK);
    sqlite3_bind_blob(statement, 2, &peer->port_id, sizeof(peer->port_id), NULL);
    sqlite3_bind_blob(statement, 3, &peer->address, sizeof(peer->address), NULL);

    ret = sqlite3_step(statement);
    if (ret != SQLITE_DONE) {
        fprintf(stderr, "Execution failed: %s\n", sqlite3_errmsg(db->handle));
        ret = -1;
        goto out;
    }

    sqlite3_finalize(statement);

    const char *delete_query =
        "DELETE FROM peers\n"
        "WHERE (subscriptions==0);";

    ret = sqlite3_prepare_v2(db->handle, delete_query, -1, &statement, 0);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->handle));
        return -1;
    }

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
