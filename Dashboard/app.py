from flask import Flask, render_template, jsonify, Response
import sqlite3
import pandas as pd
import datetime
import os
import json

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
BACKEND_DIR = os.path.join(ROOT_DIR, 'Backend')
DB_PATH = os.path.join(BACKEND_DIR, 'waf.db')               # /WAF/Backend/waf.db
LOGS_DIR = os.path.join(ROOT_DIR, 'logs')                   # /WAF/logs


# Route for Backend Status
@app.route('/')
def status():
    return render_template('index.html')


# Dashboard Route
@app.route('/dashboard')
def dashboard():
    try:

        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row

        attacks = pd.read_sql('SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 50', conn)

        thirty_days_ago = (datetime.datetime.now() - datetime.timedelta(days=30)).strftime('%Y-%m-%d')
        stats_query = '''
            SELECT
                strftime('%Y-%m-%d', timestamp) as date,
                COUNT(*) as count
            FROM attacks
            WHERE timestamp >= ?
            GROUP BY date
            ORDER BY date
        '''
        stats = pd.read_sql(stats_query, conn, params=[thirty_days_ago])

        # Fill missing dates with zero counts
        if not stats.empty:
            date_range = pd.date_range(start=stats['date'].min(), end=datetime.datetime.now().strftime('%Y-%m-%d'))
            date_range_df = pd.DataFrame({'date': date_range.strftime('%Y-%m-%d')})
            stats = pd.merge(date_range_df, stats, on='date', how='left').fillna(0)
        else:
            # Create empty dataframe with dates if no data
            today = datetime.datetime.now()
            date_range = pd.date_range(start=today - datetime.timedelta(days=30), end=today)
            stats = pd.DataFrame({
                'date': date_range.strftime('%Y-%m-%d'),
                'count': [0] * len(date_range)
            })

        # Attack types
        attack_types = pd.read_sql('''
            SELECT
                attack_type,
                COUNT(*) as count
            FROM attacks
            GROUP BY attack_type
            ORDER BY count DESC
        ''', conn)

        # Top attacker IPs
        top_ips = pd.read_sql('''
            SELECT
                ip,
                COUNT(*) as count
            FROM attacks
            GROUP BY ip
            ORDER BY count DESC
            LIMIT 5
        ''', conn)

        try:
            with open(os.path.join(LOGS_DIR, 'attack.log'), 'r', encoding='utf-8') as f:
                attack_logs = f.readlines()[-50:] if os.path.exists(os.path.join(LOGS_DIR, 'attack.log')) else []
        except Exception as e:
            attack_logs = []
            print(f"Error reading attack log: {e}")

        conn.close()

        return render_template('dashboard.html',
                               attacks=attacks.to_dict('records'),
                               dates=stats['date'].tolist(),
                               counts=stats['count'].astype(int).tolist(),
                               attack_types=attack_types.to_dict('records'),
                               top_ips=top_ips.to_dict('records'),
                               attack_logs=attack_logs[-20:])

    except Exception as e:
        print(f"Dashboard error: {e}")
        return f"Error loading dashboard data: {str(e)}", 500


# Convert bytes to string function to handle SQLite Row data
def convert_bytes(obj):
    if isinstance(obj, bytes):
        return obj.decode('utf-8', errors='replace')
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


# API Endpoint for fetching updates
@app.route('/api/updates')
def get_updates():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row

        attacks = pd.read_sql('SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 50', conn)

        thirty_days_ago = (datetime.datetime.now() - datetime.timedelta(days=30)).strftime('%Y-%m-%d')
        stats_query = '''
            SELECT
                strftime('%Y-%m-%d', timestamp) as date,
                COUNT(*) as count
            FROM attacks
            WHERE timestamp >= ?
            GROUP BY date
            ORDER BY date
        '''
        stats = pd.read_sql(stats_query, conn, params=[thirty_days_ago])

        if not stats.empty:
            date_range = pd.date_range(start=stats['date'].min(), end=datetime.datetime.now().strftime('%Y-%m-%d'))
            date_range_df = pd.DataFrame({'date': date_range.strftime('%Y-%m-%d')})
            stats = pd.merge(date_range_df, stats, on='date', how='left').fillna(0)
        else:
            today = datetime.datetime.now()
            date_range = pd.date_range(start=today - datetime.timedelta(days=30), end=today)
            stats = pd.DataFrame({
                'date': date_range.strftime('%Y-%m-%d'),
                'count': [0] * len(date_range)
            })

        # Attack type stats
        attack_types = pd.read_sql('SELECT attack_type, COUNT(*) as count FROM attacks GROUP BY attack_type', conn)

        # Unique IPs count
        unique_ips = pd.read_sql('SELECT COUNT(DISTINCT ip) as count FROM attacks', conn)

        conn.close()

        result = {
            'stats': {
                'dates': stats['date'].tolist(),
                'counts': stats['count'].astype(int).tolist(),
                'attack_count': len(attacks),
                'type_count': len(attack_types),
                'ip_count': int(unique_ips['count'].iloc[0]) if not unique_ips.empty else 0
            },
            'attacks': attacks.applymap(
                lambda x: x.decode('utf-8', errors='replace') if isinstance(x, bytes) else x
            ).to_dict('records')
        }

        response = Response(json.dumps(result, default=convert_bytes), content_type='application/json')
        response.cache_control.no_cache = True
        response.cache_control.no_store = True
        response.cache_control.must_revalidate = True
        return Response(json.dumps(result, default=convert_bytes), content_type='application/json')

    except Exception as e:
        print(f"Error fetching updates: {e}")
        return jsonify({"error": f"Failed to fetch updates: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(host='localhost', port=5000, debug=True)
