import sqlite3

def setup_database():
    conn = sqlite3.connect('waf.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            request TEXT NOT NULL,
            attack_type TEXT,
            confidence REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            pattern TEXT,
            severity INTEGER CHECK(severity BETWEEN 1 AND 5)
        )
    ''')
    
    # Add sample SQL injection rule
    cursor.execute('''
        INSERT OR IGNORE INTO rules (name, pattern, severity)
        VALUES ('SQLi Detection', ' OR ', 5)
    ''')
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    setup_database()
    print("Database initialized successfully")
