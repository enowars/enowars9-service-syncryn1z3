import sqlite3
import time
import datetime

while True:
    connection = sqlite3.connect("/data/db.sqlite")
    cursor = connection.cursor()

    cutoff_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=15)
    cursor.execute("DELETE FROM ports WHERE creation_time < ?", (cutoff_time.strftime("%Y-%m-%d %H:%M:%S"), ))

    connection.commit()
    connection.close()

    time.sleep(60)
