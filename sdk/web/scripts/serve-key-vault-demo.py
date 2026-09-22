#!/usr/bin/env python3
"""Serve the isolated password/Proton Pass test on localhost; no SDK database opens."""
import argparse
from datetime import datetime, timezone
import http.server
import json
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--port', type=int, default=8765)
args = parser.parse_args()
root = Path(__file__).resolve().parent
files = {
    '/': ('text/html; charset=utf-8', root / 'key-vault-demo.html'),
    '/key-vault-demo.js': ('text/javascript', root / 'key-vault-demo.js'),
    '/key-vault-demo.css': ('text/css', root / 'key-vault-demo.css'),
    '/key-vault.js': ('text/javascript', root.parent / 'js/key-vault.js'),
}
results = []


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args): pass
    def send(self, status, content_type, data):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(data)
    def allowed(self):
        return self.headers.get('Host') == f'localhost:{args.port}'
    def do_GET(self):
        if not self.allowed():
            self.send(403, 'text/plain', b'Use the localhost URL'); return
        if self.path == '/results':
            self.send(200, 'application/json', json.dumps(results).encode()); return
        if self.path not in files:
            self.send(404, 'text/plain', b'Not found'); return
        content_type, path = files[self.path]
        self.send(200, content_type, path.read_bytes())
    def do_POST(self):
        if (not self.allowed() or self.path != '/result' or
            self.headers.get('Origin') != f'http://localhost:{args.port}' or
            self.headers.get('Content-Type') != 'application/json'):
            self.send(403, 'text/plain', b'Refused'); return
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 2048: raise ValueError('size')
            value = json.loads(self.rfile.read(length))
            if set(value) != {'action', 'ok', 'code', 'browser'}: raise ValueError('fields')
            if value['action'] not in ['Create password vault', 'Password unlock', 'Passkey enrollment', 'Passkey unlock', 'Password change', 'Passkey password recovery']: raise ValueError('action')
            if type(value['ok']) is not bool: raise ValueError('result')
            if not isinstance(value['browser'], str) or len(value['browser']) > 512: raise ValueError('browser')
            if value['code'] not in ['ok', 'invalid-record', 'invalid-password', 'unlock-failed', 'storage-blocked', 'conflict', 'missing-key', 'already-exists', 'passkey-unavailable', 'passkey-cancelled', 'wrong-passkey', 'invalid-passkey', 'wrong-origin', 'prf-unavailable', 'missing-passkey', 'cancelled-or-unavailable', 'failed']: raise ValueError('code')
        except (ValueError, TypeError):
            self.send(400, 'text/plain', b'Invalid result'); return
        value['time'] = datetime.now(timezone.utc).isoformat()
        results.append(value)
        print(json.dumps(value), flush=True)
        self.send(200, 'application/json', b'{"recorded":true}')


server = http.server.HTTPServer(('127.0.0.1', args.port), Handler)
print(f'Key vault test: http://localhost:{args.port}/', flush=True)
try:
    server.serve_forever()
except KeyboardInterrupt:
    pass
finally:
    server.server_close()
