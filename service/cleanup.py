import sqlite3
import time
import datetime

first = True

while True:
    cutoff_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=15)

    with sqlite3.connect("/data/db.sqlite") as connection:
        cursor = connection.cursor()
        
        if first:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ports_creation_time ON ports (creation_time);")
            first = False

        cursor.execute("DELETE FROM ports WHERE creation_time < ?;", (cutoff_time.strftime("%Y-%m-%d %H:%M:%S"), ))
        connection.commit()

    time.sleep(50)
