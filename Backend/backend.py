import requests
from http.server import BaseHTTPRequestHandler, HTTPServer
import os

class BackendHandler(BaseHTTPRequestHandler):
    def serve_html(self, filename, status_code=200):
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            filepath = os.path.join(script_dir, filename)
            with open(filepath, "rb") as file:
                content = file.read()

            self.send_response(status_code)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(content)

        except FileNotFoundError:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Error: HTML file not found")

    def do_GET(self):
        waf_url = f"http://localhost:8080/verify?path={self.path}"
        
        try:
            waf_response = requests.get(waf_url)
            if waf_response.status_code == 200 and waf_response.text.strip().lower() == "allowed":
                self.serve_html("allowed.html", status_code=200)
            else:
                self.serve_html("blocked.html", status_code=403)
        except Exception as e:
            print("Error contacting WAF:", e)
            self.serve_html("error.html", status_code=500)

if __name__ == "__main__":
    server = HTTPServer(('localhost', 8000), BackendHandler)
    print("Backend server running on http://localhost:8000")
    server.serve_forever()
