import BaseHTTPServer
import SimpleHTTPServer
import ssl


httpd = BaseHTTPServer.HTTPServer(('0.0.0.0', 4443), SimpleHTTPServer.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, certfile='server.pem', server_side=True, ssl_version=ssl.PROTOCOL_SSLv23)
print("Server running on port 4443...")
httpd.serve_forever()
