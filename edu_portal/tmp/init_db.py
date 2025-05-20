# init_db.py
import sqlite3
db = '/tmp/database.db'
conn = sqlite3.connect(db)
conn.execute('CREATE TABLE IF NOT EXISTS users (...)')
conn.commit()
conn.close()
