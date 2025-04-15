from http.server import BaseHTTPRequestHandler, HTTPServer
import requests
import joblib
import sqlite3
from urllib.parse import urlparse, unquote
import pandas as pd
import logging
import os
import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__)).replace('\\', '/')
ROOT_DIR = os.path.dirname(BASE_DIR).replace('\\', '/')    
BACKEND_DIR = os.path.join(ROOT_DIR, 'Backend').replace('\\', '/')
DB_PATH = os.path.join(BACKEND_DIR, 'waf.db').replace('\\', '/')
MODEL_PATH = os.path.join(ROOT_DIR, 'models', 'waf_model.pkl').replace('\\', '/')
LOGS_DIR = os.path.join(ROOT_DIR, 'logs').replace('\\', '/')

os.makedirs(LOGS_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.DEBUG,
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
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # # Test startup write
        # conn.execute("INSERT INTO attacks (ip, request, attack_type, confid) VALUES ('127.0.0.1', 'STARTUP TEST', 'Startup', 1.0)")
        # conn.commit()
        # logging.info("Database write test successful")

        # Check schema
        cursor.execute("PRAGMA table_info(attacks)")
        columns = [col[1] for col in cursor.fetchall()]
        required = ['ip', 'request', 'attack_type', 'timestamp', 'confid']
        missing = [col for col in required if col not in columns]
        if missing:
            raise Exception(f"Missing columns in DB: {missing}")
    except Exception as e:
        logging.critical(f"Database connection failed: {e}", exc_info=True)
        os._exit(1)

init_database()

class WAFHandler(BaseHTTPRequestHandler):
    model = None

    @classmethod
    def load_model(cls):
        if cls.model is None:
            try:
                cls.model = joblib.load(MODEL_PATH)
                logging.info("Model loaded successfully")
            except Exception as e:
                logging.error(f"Error loading model: {e}", exc_info=True)
                cls.model = None
        return cls.model

    def log_attack_to_db(self, ip, request, attack_type, confidence):
        try:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute('''
                    INSERT INTO attacks (ip, request, attack_type, timestamp, confid)
                    VALUES (?, ?, ?, ?, ?)
                ''', (ip, request, attack_type, timestamp, confidence))
                conn.commit()

            msg = f"Attack detected: IP={ip}, Request={request}, Type={attack_type}, Confidence={confidence:.2f}"
            attack_logger.warning(msg)
            logging.info(f"Logged attack: {msg}")
            return True
        except Exception as e:
            logging.error(f"Database error: {e}", exc_info=True)
            return False

    def extract_features(self, path, headers):
        payload = urlparse(unquote(path)).query
        for header in ['User-Agent', 'Cookie', 'Referer']:
            payload += headers.get(header, '')

        features = {
            'length': len(payload),
            'num_semicolons': payload.count(';'),
            'has_sql_keywords': int(any(kw in payload.upper() for kw in ['SELECT', 'UNION', 'DROP', '1=1', "' OR '", '" OR "', '--'])),
            'num_special_chars': sum(c in "!@#$%^&*()+={}[]|\\:;\"'<>,?/" for c in payload),
            'has_http_methods': int(any(method in payload.upper() for method in ['GET', 'POST', 'PUT', 'DELETE']))
        }

        logging.debug(f"Extracted features: {features}")
        return features

    def do_GET(self):
        client_ip = self.client_address[0]
        logging.info(f"Incoming request from {client_ip}: {self.path}")

        whitelist = ["/safe-path?param=value", "/another-safe-test?example=1"]
        if self.path.startswith("/verify"):
            requested_path = self.path.split("path=")[-1]
            self.send_response(200 if requested_path in whitelist else 403)
            self.end_headers()
            self.wfile.write(b"allowed" if requested_path in whitelist else b"denied")
            return

        if self.path in whitelist:
            logging.info("Request matches whitelist. Forwarding.")
            self.forward_request()
            return

        if not WAFHandler.model:
            WAFHandler.load_model()

        try:
            features = self.extract_features(self.path, self.headers)
            features_df = pd.DataFrame([features])
            logging.debug(f"Features for model: {features_df}")

            if WAFHandler.model:
                prediction_proba = WAFHandler.model.predict_proba(features_df)[0][1]
                confidence = prediction_proba

                logging.info(f"Prediction Probability: {confidence:.4f}")

            if confidence > 0.5:
                attack_type = self.detect_attack_type(self.path)
                if self.log_attack_to_db(client_ip, self.path, attack_type, confidence):
                    self.send_block_response()
                    return

                else:
                    logging.info("Request not flagged as attack (confidence below threshold).")
            else:
                logging.warning("Model not loaded. Cannot classify request.")

            self.forward_request()

        except Exception as e:
            logging.error(f"Error processing request: {e}", exc_info=True)
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
            with open(os.path.join(BACKEND_DIR, "blocked.html"), "rb") as f:
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
