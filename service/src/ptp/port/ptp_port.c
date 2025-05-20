#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sqlite3.h>

#include <ptp/port/ptp_port.h>
#include <ptp/ptp_helper.h>

#define PTP_PORT_DB_CACHE_SIZE 256

static inline int ptp_port_db_hash(struct ptp_decoded_port_id port_id) {
    return (port_id.clock_id + port_id.port) % PTP_PORT_DB_CACHE_SIZE;
}

static inline int ptp_port_db_valid(struct ptp_decoded_port_id port_id) {
    // Only allow locally administered OUI range
    if (((port_id.clock_id >> 56) & 0xff) != 0x02) {
        return -EINVAL;
    }

    // Do not allow special ports
    if (port_id.port == 0 || port_id.port == 0xffff) {
        return -EINVAL;
    }

    return 0;
}

int ptp_port_db_setup(struct ptp_port_db *db, const char *filename) {
    int ret;
    char *error_message;

    ret = sqlite3_open(filename, &db->handle);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "Failed to open database: %s\n", sqlite3_errmsg(db->handle));
        return -1;
    }

    const char *pragma_query = "PRAGMA journal_mode=WAL;";
    ret = sqlite3_exec(db->handle, pragma_query, 0, 0, &error_message);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", error_message);
        sqlite3_free(error_message);
        return -1;
    }

    const char *create_query =
        "CREATE TABLE IF NOT EXISTS\n"
        "ports(clock_id INTEGER NOT NULL, port INTEGER NOT NULL, authentication_policy INTEGER, secret TEXT, user_description TEXT, UNIQUE(clock_id, port));";

    ret = sqlite3_exec(db->handle, create_query, 0, 0, &error_message);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", error_message);
        sqlite3_free(error_message);
        return -1;
    }

    db->cache = calloc(PTP_PORT_DB_CACHE_SIZE, sizeof(struct ptp_port_entry));
    if (!db->cache) {
        return -ENOMEM;
    }

    return 0;
}

int ptp_port_db_cleanup(struct ptp_port_db *db) {
    int ret;
    
    ret = sqlite3_close(db->handle);
    if (ret != SQLITE_OK) {
        return -1;
    }

    free(db->cache);

    return 0;
}

int ptp_port_db_get(struct ptp_port_db *db, struct ptp_port_entry **entry, struct ptp_decoded_port_id port_id) {
    int ret;
    char *error_message;
    sqlite3_stmt *statement;

    ret = ptp_port_db_valid(port_id);
    if (ret) {
        return ret;
    }

    *entry = &db->cache[ptp_port_db_hash(port_id)];
    if (!ptp_compare_port_id((*entry)->port_id, port_id)) {
        return 0;
    }

    const char *select_query =
        "SELECT authentication_policy, secret, user_description FROM ports\n"
        "WHERE (clock_id==? AND port==?);";

    ret = sqlite3_prepare_v2(db->handle, select_query, -1, &statement, 0);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->handle));
        return -1;
    }

    sqlite3_bind_int64(statement, 1, port_id.clock_id);
    sqlite3_bind_int(statement, 2, port_id.port);

    ret = sqlite3_step(statement);
    if (ret != SQLITE_ROW) {
        if (ret == SQLITE_DONE) {
            (*entry)->active = false;
            ret = 0;
        } else {
            fprintf(stderr, "Execution failed: %s\n", sqlite3_errmsg(db->handle));
            ret = -1;
        }

        goto out;
    }

    (*entry)->port_id.clock_id = port_id.clock_id;
    (*entry)->port_id.port = port_id.port;
    (*entry)->active = true;
    (*entry)->authentication_policy = sqlite3_column_int(statement, 0);
    memcpy(&(*entry)->secret, sqlite3_column_text(statement, 1), PTP_PORT_SECRET_SIZE);
    memcpy(&(*entry)->user_description, sqlite3_column_text(statement, 2), PTP_USER_DESCRIPTION_SIZE);

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

int ptp_port_db_set(struct ptp_port_db *db, struct ptp_port_entry *entry) {
    int ret;
    char *error_message;
    sqlite3_stmt *statement;

    ret = ptp_port_db_valid(entry->port_id);
    if (ret) {
        return ret;
    }

    // Invalidate cache
    db->cache[ptp_port_db_hash(entry->port_id)].port_id.port = 0;

    if (entry->active) {
        const char *insert_query =
            "INSERT OR REPLACE INTO ports(clock_id, port, authentication_policy, secret, user_description)\n"
            "VALUES (?, ?, ?, ?, ?);";

        ret = sqlite3_prepare_v2(db->handle, insert_query, -1, &statement, 0);
        if (ret != SQLITE_OK) {
            fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->handle));
            return -1;
        }

        sqlite3_bind_int64(statement, 1, entry->port_id.clock_id);
        sqlite3_bind_int(statement, 2, entry->port_id.port);
        sqlite3_bind_int(statement, 3, entry->authentication_policy);
        sqlite3_bind_text(statement, 4, entry->secret, PTP_PORT_SECRET_SIZE, NULL);
        sqlite3_bind_text(statement, 5, entry->user_description, PTP_USER_DESCRIPTION_SIZE, NULL);
    } else {
        const char *delete_query =
            "DELETE FROM ports\n"
            "WHERE (clock_id==? AND port==?);";

        ret = sqlite3_prepare_v2(db->handle, delete_query, -1, &statement, 0);
        if (ret != SQLITE_OK) {
            fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->handle));
            return -1;
        }

        sqlite3_bind_int64(statement, 1, entry->port_id.clock_id);
        sqlite3_bind_int(statement, 2, entry->port_id.port);
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
