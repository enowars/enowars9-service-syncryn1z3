#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <sqlite3.h>

#include <ptp/port/ptp_port.h>

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
        "ports(port INTEGER PRIMARY KEY, authentication_policy INTEGER, secret TEXT, user_description TEXT);";

    ret = sqlite3_exec(db->handle, create_query, 0, 0, &error_message);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", error_message);
        sqlite3_free(error_message);
        return -1;
    }

    return 0;
}

int ptp_port_db_cleanup(struct ptp_port_db *db) {
    sqlite3_close(db->handle);

    return 0;
}

int ptp_port_db_get(struct ptp_port_db *db, struct ptp_port_entry *entry) {
    int ret;
    char *error_message;
    sqlite3_stmt *statement;

    const char *select_query =
        "SELECT authentication_policy, secret, user_description FROM ports\n"
        "WHERE (port==?);";

    ret = sqlite3_prepare_v2(db->handle, select_query, -1, &statement, 0);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->handle));
        return -1;
    }

    sqlite3_bind_int(statement, 1, entry->port);

    ret = sqlite3_step(statement);
    if (ret != SQLITE_ROW) {
        if (ret == SQLITE_DONE) {
            entry->active = false;
            ret = 0;
        } else {
            fprintf(stderr, "Execution failed: %s\n", sqlite3_errmsg(db->handle));
            ret = -1;
        }

        goto out;
    }

    entry->active = true;
    entry->authentication_policy = sqlite3_column_int(statement, 0);
    memcpy(&entry->secret, sqlite3_column_text(statement, 1), PTP_PORT_SECRET_SIZE);
    memcpy(&entry->user_description, sqlite3_column_text(statement, 2), PTP_USER_DESCRIPTION_SIZE);

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

    if (entry->active) {
        const char *insert_query =
            "INSERT OR REPLACE INTO ports(port, authentication_policy, secret, user_description)\n"
            "VALUES (?, ?, ?, ?);";

        ret = sqlite3_prepare_v2(db->handle, insert_query, -1, &statement, 0);
        if (ret != SQLITE_OK) {
            fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->handle));
            return -1;
        }

        sqlite3_bind_int(statement, 1, entry->port);
        sqlite3_bind_int(statement, 2, entry->authentication_policy);
        sqlite3_bind_text(statement, 3, entry->secret, PTP_PORT_SECRET_SIZE, NULL);
        sqlite3_bind_text(statement, 4, entry->user_description, PTP_USER_DESCRIPTION_SIZE, NULL);
    } else {
        const char *delete_query =
            "DELETE FROM ports\n"
            "WHERE (port==?);";

        ret = sqlite3_prepare_v2(db->handle, delete_query, -1, &statement, 0);
        if (ret != SQLITE_OK) {
            fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db->handle));
            return -1;
        }

        sqlite3_bind_int(statement, 1, entry->port);
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
