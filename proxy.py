from http.server import BaseHTTPRequestHandler, HTTPServer
import requests
import joblib
import sqlite3
from urllib.parse import urlparse, unquote

model = joblib.load('waf_model.pkl')

class WAFHandler(BaseHTTPRequestHandler):
    def extract_features(self, path):
        decoded_path = unquote(path) 
        parsed = urlparse(decoded_path)
        query = parsed.query
        
        return {
            'length': len(query),
            'num_semicolons': query.count(';'),
            'has_sql_keywords': int(any(
                kw in query.upper() 
                for kw in ['SELECT', 'UNION', 'DROP', ' OR ', '1=1']
            ))
        }


    def log_attack(self, ip, request):
        conn = sqlite3.connect('waf.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO attacks (ip, request) VALUES (?, ?)', 
                      (ip, request))
        conn.commit()
        conn.close()

    def do_GET(self):
        client_ip = self.client_address[0]
        features = self.extract_features(self.path)

        print(f"🔍 Extracted Features: {features}")  # Debug print

        if model.predict([list(features.values())])[0] == 1:
            self.log_attack(client_ip, self.path)
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Blocked by AI WAF")
        else:
            try:
                response = requests.get(f"http://localhost:8000{self.path}")
                self.send_response(response.status_code)
                self.end_headers()
                self.wfile.write(response.content)
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(str(e).encode())

# ✅ Fix: run() function is OUTSIDE the class
def run(server=HTTPServer, port=8080):
    server_address = ('', port)
    httpd = server(server_address, WAFHandler)
    print(f"WAF running on port {port}")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
