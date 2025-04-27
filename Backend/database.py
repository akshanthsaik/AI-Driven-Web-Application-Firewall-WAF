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
    
    # Clear existing rules
    cursor.execute('DELETE FROM rules')
    
    # Add comprehensive SQL injection rules
    sql_patterns = [
        ('SQLi OR Pattern', ' OR ', 5),
        ('SQLi Union Pattern', 'UNION SELECT', 5),
        ('SQLi Comment Pattern', '--', 4),
        ('SQLi Equal Pattern', '1=1', 5),
        ('SQLi Quote Pattern', "' OR '", 5),
        ('SQLi Double Quote Pattern', '" OR "', 5),
        ('SQLi Sleep Pattern', 'SLEEP(', 4),
        ('SQLi Admin Pattern', "' OR 1=1 --", 5),
        ('SQLi Apostrophe', "'", 3),
        ('SQLi Semicolon', ";", 3),
        ('SQLi Drop', "DROP", 5),
        ('SQLi Select', "SELECT", 4)
    ]
    
    cursor.executemany('''
        INSERT INTO rules (name, pattern, severity)
        VALUES (?, ?, ?)
    ''', sql_patterns)
    
    conn.commit()
    conn.close()
    print(" Database initialized with rules")

if __name__ == "__main__":
    setup_database()
