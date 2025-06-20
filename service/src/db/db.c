#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sqlite3.h>

#include <db/db.h>
#include <ptp/ptp_helper.h>
#include <ptp/protocol/ptp_decoded.h>

#define DB_CACHE_SIZE 256

static inline int db_hash(struct ptp_decoded_port_id port_id) {
    return (port_id.clock_id + port_id.port) % DB_CACHE_SIZE;
}

static inline int db_valid(struct ptp_decoded_port_id port_id) {
    /// Do not allow special clocks
    if (port_id.clock_id == 0 || port_id.clock_id == 0xffffffffffffffff) {
        return -EINVAL;
    }

    // Do not allow special ports
    if (port_id.port == 0 || port_id.port == 0xffff) {
        return -EINVAL;
    }

    return 0;
}

int db_setup(struct db_state *state, struct db_config *config) {
    int ret;
    char *error_message;

    ret = sqlite3_open(config->filename, &state->handle);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "Failed to open database: %s\n", sqlite3_errmsg(state->handle));
        return -1;
    }

    // Set busy timeout to avoid conflicts with cleanup script
    sqlite3_busy_timeout(state->handle, 2000);

    const char *create_query =
        "CREATE TABLE IF NOT EXISTS\n"
        "ports(clock_id INTEGER NOT NULL, port INTEGER NOT NULL, authentication_policy INTEGER, offset INTEGER, visible BOOLEAN, user_description BLOB, secret TEXT, creation_time DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(clock_id, port));";

    ret = sqlite3_exec(state->handle, create_query, 0, 0, &error_message);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", error_message);
        sqlite3_free(error_message);
        return -1;
    }

    state->cache = calloc(DB_CACHE_SIZE, sizeof(struct db_entry));
    if (!state->cache) {
        return -ENOMEM;
    }

    return 0;
}

int db_cleanup(struct db_state *state) {
    int ret;
    
    ret = sqlite3_close(state->handle);
    if (ret != SQLITE_OK) {
        return -1;
    }

    free(state->cache);

    return 0;
}

int db_get(struct db_state *state, struct db_entry **entry, struct ptp_decoded_port_id port_id) {
    int ret;
    char *error_message;
    sqlite3_stmt *statement;

    ret = db_valid(port_id);
    if (ret) {
        return ret;
    }

    *entry = &state->cache[db_hash(port_id)];
    if (!ptp_compare_port_id((*entry)->port_id, port_id) && (*entry)->valid) {
        return 0;
    }

    const char *select_query =
        "SELECT authentication_policy, offset, visible, user_description, length(user_description), secret FROM ports\n"
        "WHERE (clock_id==? AND port==?);";

    ret = sqlite3_prepare_v2(state->handle, select_query, -1, &statement, 0);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(state->handle));
        return -1;
    }

    sqlite3_bind_int64(statement, 1, port_id.clock_id);
    sqlite3_bind_int(statement, 2, port_id.port);

    ret = sqlite3_step(statement);
    if (ret != SQLITE_ROW) {
        if (ret == SQLITE_DONE) {
            ret = -ENODATA;
        } else {
            fprintf(stderr, "Execution failed: %s\n", sqlite3_errmsg(state->handle));
            ret = -1;
        }

        goto out;
    }

    (*entry)->port_id.clock_id = port_id.clock_id;
    (*entry)->port_id.port = port_id.port;
    (*entry)->valid = true;
    (*entry)->authentication_policy = sqlite3_column_int(statement, 0);
    (*entry)->offset = sqlite3_column_int64(statement, 1);
    (*entry)->visible = sqlite3_column_int(statement, 2);
    (*entry)->user_description_length = sqlite3_column_int(statement, 4);
    memcpy((*entry)->user_description, sqlite3_column_blob(statement, 3), (*entry)->user_description_length);
    strcpy((*entry)->secret, (const char *)sqlite3_column_text(statement, 5));

    ret = sqlite3_step(statement);
    if (ret != SQLITE_DONE) {
        fprintf(stderr, "Execution failed: %s\n", sqlite3_errmsg(state->handle));
        ret = -1;
        goto out;
    }

    ret = 0;

out:
    sqlite3_finalize(statement);

    return ret;
}

int db_get_recent(struct db_state *state, struct db_entry **entries, short length) {
    int ret;
    char *error_message;
    sqlite3_stmt *statement;

    const char *select_query =
        "SELECT clock_id, port, authentication_policy, offset, visible, user_description, length(user_description), secret FROM ports\n"
        "WHERE visible\n"
        "ORDER BY creation_time DESC LIMIT ?;";

    ret = sqlite3_prepare_v2(state->handle, select_query, -1, &statement, 0);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(state->handle));
        return -1;
    }

    sqlite3_bind_int(statement, 1, length);

    for (int i = 0; i < length; ++i) {
        ret = sqlite3_step(statement);
        if (ret != SQLITE_ROW) {
            if (ret == SQLITE_DONE) {
                ret = 0;
            } else {
                fprintf(stderr, "Execution failed: %s\n", sqlite3_errmsg(state->handle));
                ret = -1;
            }

            entries[i] = NULL;

            goto out;
        }

        struct ptp_decoded_port_id port_id;
        port_id.clock_id = sqlite3_column_int64(statement, 0);
        port_id.port = sqlite3_column_int(statement, 1);

        entries[i] = &state->cache[db_hash(port_id)];
        entries[i]->port_id = port_id;
        entries[i]->valid = true;
        entries[i]->authentication_policy = sqlite3_column_int(statement, 2);
        entries[i]->offset = sqlite3_column_int64(statement, 3);
        entries[i]->visible = sqlite3_column_int(statement, 4);
        entries[i]->user_description_length = sqlite3_column_int(statement, 6);
        memcpy(entries[i]->user_description, sqlite3_column_blob(statement, 5), entries[i]->user_description_length);
        strcpy(entries[i]->secret, (const char *)sqlite3_column_text(statement, 7));
    }

    ret = 0;

out:
    sqlite3_finalize(statement);

    return ret;
}

int db_set(struct db_state *state, struct db_entry *entry) {
    int ret;
    char *error_message;
    sqlite3_stmt *statement;

    ret = db_valid(entry->port_id);
    if (ret) {
        return ret;
    }

    if (entry->user_description_length > DB_USER_DESCRIPTION_SIZE) {
        return -EINVAL;
    }

    // Invalidate cache
    state->cache[db_hash(entry->port_id)].valid = false;

    const char *insert_query =
        "INSERT INTO ports(clock_id, port, authentication_policy, offset, visible, user_description, secret)\n"
        "VALUES (?, ?, ?, ?, ?, ?, ?);";

    ret = sqlite3_prepare_v2(state->handle, insert_query, -1, &statement, 0);
    if (ret != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(state->handle));
        return -1;
    }

    sqlite3_bind_int64(statement, 1, entry->port_id.clock_id);
    sqlite3_bind_int(statement, 2, entry->port_id.port);
    sqlite3_bind_int(statement, 3, entry->authentication_policy);
    sqlite3_bind_int64(statement, 4, entry->offset);
    sqlite3_bind_int(statement, 5, entry->visible);
    sqlite3_bind_blob(statement, 6, entry->user_description, entry->user_description_length, NULL);
    sqlite3_bind_text(statement, 7, entry->secret, DB_SECRET_SIZE, NULL);

    ret = sqlite3_step(statement);
    if (ret != SQLITE_DONE) {
        if (ret != SQLITE_CONSTRAINT) {
            fprintf(stderr, "Execution failed: %s\n", sqlite3_errmsg(state->handle));
        }

        ret = -1;
        goto out;
    }

    ret = 0;

out:
    sqlite3_finalize(statement);

    return ret;
}
