# app.py
from flask import Flask, render_template
import sqlite3
import pandas as pd

app = Flask(__name__)

@app.route('/')
def dashboard():
    conn = sqlite3.connect('waf.db')
    
    # Attack statistics
    attacks = pd.read_sql('SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 50', conn)
    stats = pd.read_sql('''
        SELECT strftime('%Y-%m-%d', timestamp) as date, 
               COUNT(*) as count 
        FROM attacks 
        GROUP BY date
    ''', conn)
    
    conn.close()
    
    return render_template('dashboard.html',
                         attacks=attacks.to_dict('records'),
                         dates=stats['date'].tolist(),
                         counts=stats['count'].tolist())

if __name__ == "__main__":
    app.run(port=5000)
