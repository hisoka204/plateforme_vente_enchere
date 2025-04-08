import sqlite3

conn = sqlite3.connect('data.db')
cursor = conn.cursor()

# table user
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username ARCHAR(25),
    password TEXT NOT NULL,
    salt TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    is_verified INTEGER DEFAULT 0,
    verification_code TEXT
)
''')

# table auctions
cursor.execute('''
CREATE TABLE IF NOT EXISTS auctions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title VARCHAR(100),
    creation_date DATE TIME,
    expiration_date DATE TIME,
    expired INTEGER,
    description TEXT,
    price FLOAT,
    current_price FLOAT,
    user_id INTEGER NOT NULL,
    last_bidder_id INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (last_bidder_id) REFERENCES users(id)
)
''')

conn.commit()
conn.close()