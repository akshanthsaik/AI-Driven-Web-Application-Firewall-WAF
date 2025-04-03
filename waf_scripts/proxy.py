from http.server import BaseHTTPRequestHandler, HTTPServer
import requests
import joblib
import sqlite3
from urllib.parse import urlparse, unquote
import pandas as pd
import logging
import os
import datetime

# Configure paths based on project structure
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # waf_scripts directory
ROOT_DIR = os.path.dirname(BASE_DIR)                   # Root WAF directory
BACKEND_DIR = os.path.join(ROOT_DIR, 'Backend')        # Backend directory
DB_PATH = os.path.join(BACKEND_DIR, 'waf.db')          # Use the Backend/waf.db file
MODEL_PATH = os.path.join(ROOT_DIR, 'models', 'waf_model.pkl')
LOGS_DIR = os.path.join(ROOT_DIR, 'logs')

# Ensure directories exist
os.makedirs(LOGS_DIR, exist_ok=True)

# Configure logging with UTF-8 encoding
logging.basicConfig(
    level=logging.INFO,
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
attack_logger.propagate = False  # Prevent duplicate logs

print(f"Using database at: {DB_PATH}")
print(f"Using model at: {MODEL_PATH}")
print(f"Logging to: {LOGS_DIR}")

# Initialize database schema if not exists
def init_database():
    with sqlite3.connect(DB_PATH) as conn:
        # Make sure schema matches what dashboard expects
        conn.execute('''
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                request TEXT NOT NULL,
                attack_type TEXT,
                timestamp TEXT DEFAULT (datetime('now', 'localtime'))
            )
        ''')
        conn.commit()
        logging.info(f"Database initialized at {DB_PATH}")
        
        # Verify table exists and can be accessed
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='attacks'")
        if cursor.fetchone():
            logging.info("✅ Table 'attacks' verified")
        else:
            logging.error("❌ Table 'attacks' not found in database")

init_database()

class WAFHandler(BaseHTTPRequestHandler):
    model = None  # Class variable to store the model
    
    @classmethod
    def load_model(cls):
        """Load the model once at server startup"""
        if cls.model is None:
            try:
                cls.model = joblib.load(MODEL_PATH)
                logging.info("✅ Model loaded successfully")
            except Exception as e:
                logging.error(f"❌ Error loading model: {e}")
                cls.model = None
        return cls.model

    def log_attack_to_db(self, ip, request, attack_type, confidence):
        """Log attack details to the database and attack.log."""
        try:
            # Format timestamp in a way compatible with dashboard
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            with sqlite3.connect(DB_PATH) as conn:
                # Insert using the schema expected by the dashboard
                conn.execute('''
                    INSERT INTO attacks (ip, request, attack_type, timestamp)
                    VALUES (?, ?, ?, ?)
                ''', (ip, request, attack_type, timestamp))
                conn.commit()
                
                # Log to file
                attack_log_entry = f"Attack detected: IP={ip}, Request={request}, Type={attack_type}, Confidence={confidence:.2f}"
                attack_logger.warning(attack_log_entry)
                logging.info(f"✅ Attack logged to database: {ip} - {attack_type}")
                
                # Verify the data was written
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM attacks WHERE ip=? AND timestamp=?", (ip, timestamp))
                count = cursor.fetchone()[0]
                if count > 0:
                    logging.info(f"✅ Verified attack record in database")
                else:
                    logging.error("❌ Failed to verify attack record in database")
        except Exception as e:
            logging.error(f"❌ Database error: {e}")

    def extract_features(self, path, headers):
        """Extract features from the request for classification."""
        payload = urlparse(unquote(path)).query
        for header in ['User-Agent', 'Cookie', 'Referer']:
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
        """Handle incoming GET requests."""
        client_ip = self.client_address[0]
        logging.info(f"Request from {client_ip}: {self.path}")

        # For testing purposes - always log some attacks to verify dashboard integration
        if 'test-attack' in self.path:
            attack_type = "Test Attack"
            self.log_attack_to_db(client_ip, self.path, attack_type, 0.95)
            self.send_response(403)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"Test attack logged")
            return

        # Load model if not loaded
        if WAFHandler.model is None:
            WAFHandler.load_model()

        try:
            # Extract features for prediction
            features = self.extract_features(self.path, self.headers)
            features_df = pd.DataFrame([features])

            if WAFHandler.model:
                prediction = WAFHandler.model.predict(features_df)[0]
                probabilities = WAFHandler.model.predict_proba(features_df)[0]
                confidence = probabilities[1]

                if prediction == 1 and confidence > 0.7:
                    # Log attack details to both database and log file
                    attack_type = self.detect_attack_type(self.path)
                    self.log_attack_to_db(client_ip, self.path, attack_type, confidence)

                    # Block the request
                    self.send_response(403)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b"Blocked by AI WAF")
                    return

            # Forward legitimate requests to upstream server
            try:
                response = requests.get(f"http://localhost:8000{self.path}", 
                                       headers={k: v for k, v in self.headers.items() 
                                               if k.lower() not in ('host',)}, 
                                       timeout=10)
                
                self.send_response(response.status_code)
                
                # Copy response headers
                for header, value in response.headers.items():
                    if header.lower() not in ('server', 'date', 'content-length'):
                        self.send_header(header, value)
                
                self.end_headers()
                self.wfile.write(response.content)
            except requests.RequestException as e:
                logging.error(f"Request to upstream server failed: {e}")
                self.send_response(502)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b"Error reaching upstream server")

        except Exception as e:
            logging.error(f"Request handling error: {e}")
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"Internal Server Error")

    def detect_attack_type(self, path):
        """Determine the type of attack based on request content."""
        path = path.upper()
        if any(kw in path for kw in ['SELECT', 'UNION', 'DROP TABLE', 'OR 1=1']):
            return "SQL Injection"
        if any(kw in path for kw in ['SCRIPT', '<', 'JAVASCRIPT:', 'ALERT(']):
            return "XSS"
        if path.count('=') > 3 or len(path) > 100:
            return "Parameter Tampering"
        if "/../" in path or "/.." in path:
            return "Path Traversal"
        if path.count('/') > 5:
            return "Directory Scanning"
        return "Suspicious Request"

def run():
    """Run the WAF proxy server."""
    # Create a test attack record to verify database connection
    with sqlite3.connect(DB_PATH) as conn:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute('''
            INSERT INTO attacks (ip, request, attack_type, timestamp)
            VALUES (?, ?, ?, ?)
        ''', ('127.0.0.1', '/startup-test', 'Server Start', timestamp))
        conn.commit()
        logging.info("✅ Startup test record added to database")
    
    # Load model once at startup
    WAFHandler.load_model()
    
    server = HTTPServer(('', 8080), WAFHandler)
    logging.info("✅ WAF Proxy Server started on port 8080")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("🛑 Shutting down WAF Proxy Server")
    finally:
        server.server_close()

if __name__ == "__main__":
    run()
