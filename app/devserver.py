#!/usr/bin/env python3
from http.server import HTTPServer, SimpleHTTPRequestHandler, test
import sys
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
dist_path = os.path.join(current_dir, '..', 'dist')
os.chdir(dist_path)

class RequestHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        self.send_header('Cross-Origin-Embedder-Policy', 'require-corp')
        SimpleHTTPRequestHandler.end_headers(self)

if __name__ == '__main__':
    print("===> Open your browser at http://localhost:8000/")
    test(RequestHandler, HTTPServer, port=8000)