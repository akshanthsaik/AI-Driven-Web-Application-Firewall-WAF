from http.server import BaseHTTPRequestHandler, HTTPServer
import requests
import joblib
import sqlite3
from urllib.parse import urlparse, unquote
import pandas as pd
import logging
import os
import datetime
import xgboost  # Required for proper model loading

# Configure paths with raw strings for Windows compatibility
BASE_DIR = os.path.dirname(os.path.abspath(__file__)).replace('\\', '/')
ROOT_DIR = os.path.dirname(BASE_DIR).replace('\\', '/')    
BACKEND_DIR = os.path.join(ROOT_DIR, 'Backend').replace('\\', '/')
DB_PATH = os.path.join(BACKEND_DIR, 'waf.db').replace('\\', '/')
MODEL_PATH = os.path.join(ROOT_DIR, 'models', 'waf_model_new.pkl').replace('\\', '/')
LOGS_DIR = os.path.join(ROOT_DIR, 'logs').replace('\\', '/')

# Ensure directories exist
os.makedirs(LOGS_DIR, exist_ok=True)

# Configure logging with UTF-8 encoding
logging.basicConfig(
    level=logging.DEBUG,  # Temporarily set to DEBUG for troubleshooting
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOGS_DIR, "access.log"), encoding='utf-8'),
        logging.StreamHandler()
    ]
)

attack_logger = logging.getLogger("attack")
attack_logger.setLevel(logging.WARNING)
attack_handler = logging.FileHandler(os.path.join(LOGS_DIR, "attack.log"), encoding='utf-8')
attack_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
attack_logger.addHandler(attack_handler)
attack_logger.propagate = False

print(f"Using database at: {DB_PATH}")
print(f"Using model at: {MODEL_PATH}")
print(f"Logging to: {LOGS_DIR}")

def init_database():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                request TEXT NOT NULL,
                attack_type TEXT,
                timestamp TEXT DEFAULT (datetime('now', 'localtime')),
                confid REAL
            )
        ''')
        conn.commit()
        logging.info(f"Database initialized at {DB_PATH}")
        
        # Verify table structure
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(attacks)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'confid' not in columns:
            logging.error("Missing 'confid' column in attacks table")
            conn.execute('ALTER TABLE attacks ADD COLUMN confid REAL')
            conn.commit()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='attacks'")
        if not cursor.fetchone():
            logging.error("Table 'attacks' not found in database")

init_database()

class WAFHandler(BaseHTTPRequestHandler):
    model = None
    
    @classmethod
    def load_model(cls):
        if cls.model is None:
            try:
                # Load model using XGBoost's native interface
                cls.model = xgboost.Booster()
                cls.model.load_model(MODEL_PATH)
                logging.info("XGBoost model loaded successfully")
            except Exception as e:
                logging.error(f"Error loading model: {e}", exc_info=True)
        return cls.model

    def log_attack_to_db(self, ip, request, attack_type, confidence):
        """Log attack details to the database and attack.log."""
        try:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute('''
                    INSERT INTO attacks (ip, request, attack_type, timestamp, confid)
                    VALUES (?, ?, ?, ?, ?)
                ''', (ip, request, attack_type, timestamp, confidence))
                conn.commit()
                
                attack_log_entry = f"Attack detected: IP={ip}, Request={request}, Type={attack_type}, Confidence={confidence:.2f}"
                attack_logger.warning(attack_log_entry)
                logging.info(f"Logged attack: {attack_log_entry}")
                
                return True
        except Exception as e:
            logging.error(f"Database error: {str(e)}", exc_info=True)
            return False

    def extract_features(self, path, headers):
        payload = urlparse(unquote(path)).query
        for header in ['User-Agent', 'Cookie', 'Referer']:
            if header in headers:
                payload += headers.get(header, '')
        
        return {
            'length': len(payload),
            'num_semicolons': payload.count(';'),
            'has_sql_keywords': int(any(
                kw in payload.upper() for kw in ['SELECT', 'UNION', 'DROP', '1=1', "' OR '", '" OR "', '--']
            )),
            'num_special_chars': sum(c in "!@#$%^&*()+={}[]|\\:;\"'<>,?/" for c in payload),
            'has_http_methods': int(any(method in payload.upper() for method in ['GET', 'POST', 'PUT', 'DELETE']))
        }

    def do_GET(self):
        client_ip = self.client_address[0]
        logging.info(f"Request from {client_ip}: {self.path}")

        # Whitelist handling
        whitelist = ["/safe-path?param=value", "/another-safe-test?example=1"]
        if self.path.startswith("/verify"):
            requested_path = self.path.split("path=")[-1]
            self.send_response(200 if requested_path in whitelist else 403)
            self.end_headers()
            self.wfile.write(b"allowed" if requested_path in whitelist else b"denied")
            return

        if self.path in whitelist:
            self.forward_request()
            return

        # Load model if not loaded
        if not WAFHandler.model:
            WAFHandler.load_model()

        try:
            features = self.extract_features(self.path, self.headers)
            features_df = pd.DataFrame([features])
            logging.debug(f"Features: {features}")

            if WAFHandler.model:
                # Convert features to DMatrix for XGBoost
                dmatrix = xgboost.DMatrix(features_df)
                prediction = WAFHandler.model.predict(dmatrix)[0]
                confidence = prediction  # For binary classification, probability is direct
                
                logging.info(f"Prediction: {prediction}, Confidence: {confidence:.2f}")

                if confidence > 0.5:  # Lowered threshold for testing
                    attack_type = self.detect_attack_type(self.path)
                    if self.log_attack_to_db(client_ip, self.path, attack_type, confidence):
                        self.send_block_response()
                        return

            self.forward_request()

        except Exception as e:
            logging.error(f"Request error: {e}", exc_info=True)
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Internal Server Error")

    def detect_attack_type(self, path):
        path_upper = path.upper()
        if any(kw in path_upper for kw in ['SELECT', 'UNION', 'DROP TABLE', 'OR 1=1']):
            return "SQL Injection"
        if any(kw in path_upper for kw in ['SCRIPT', '<', 'JAVASCRIPT:', 'ALERT(']):
            return "XSS"
        if path.count('=') > 3 or len(path) > 100:
            return "Parameter Tampering"
        if "/../" in path or "/.." in path:
            return "Path Traversal"
        if path.count('/') > 5:
            return "Directory Scanning"
        return "Suspicious Request"

    def forward_request(self):
        try:
            response = requests.get(
                f"http://localhost:8000{self.path}",
                headers={k: v for k, v in self.headers.items() if k.lower() != 'host'},
                timeout=10
            )
            self.send_response(response.status_code)
            for header, value in response.headers.items():
                if header.lower() not in ('server', 'date', 'content-length'):
                    self.send_header(header, value)
            self.end_headers()
            self.wfile.write(response.content)
        except requests.RequestException as e:
            logging.error(f"Upstream error: {e}")
            self.send_response(502)
            self.end_headers()
            self.wfile.write(b"Upstream server error")

    def send_block_response(self):
        self.send_response(403)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        try:
            with open("blocked.html", "rb") as f:
                self.wfile.write(f.read())
        except FileNotFoundError:
            self.wfile.write(b"Blocked by WAF")

def run():
    WAFHandler.load_model()
    server = HTTPServer(('', 8080), WAFHandler)
    logging.info("WAF running on port 8080")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Shutting down WAF")
    finally:
        server.server_close()

if __name__ == "__main__":
    run()
