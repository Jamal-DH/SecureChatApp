# import sqlite3, pprint, utils.db_setup as d
# conn = sqlite3.connect(d.DB_PATH); cur = conn.cursor()
# try:
#     cur.execute("PRAGMA table_info(users)")
#     print("Columns:", [c[1] for c in cur.fetchall()])
#     cur.execute("SELECT username, role, usb_serial FROM users WHERE username='ahmad'")
#     row = cur.fetchone(); print("Statement row:", row)
# finally:
#     conn.close()
"""
download alexcvzz 
"""
import sqlite3
import pprint
import utils.db_setup as d

# Connect to the database using the provided DB_PATH.
conn = sqlite3.connect(d.DB_PATH)
cur = conn.cursor()

try:
    # Retrieve the table information to see all available columns in the "users" table.
    cur.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in cur.fetchall()]
    print("Columns available:", columns)

    # Query to get all records and all columns from the "users" table.
    cur.execute("SELECT * FROM users")
    users_data = cur.fetchall()

    # Print out each row as a dictionary mapping column names to values.
    print("All users information:")
    for row in users_data:
        user_info = dict(zip(columns, row))
        pprint.pprint(user_info)
finally:
    # Always close the connection.
    conn.close()
