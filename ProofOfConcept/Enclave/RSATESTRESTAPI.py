from flask import Flask, request, jsonify
import argparse
import socket
import sys
import json

class VsockStream:
    """Client"""
    def __init__(self, conn_tmo=5):
        self.conn_tmo = conn_tmo

    def connect(self, endpoint):
        """Connect to the remote endpoint"""
        self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        self.sock.settimeout(self.conn_tmo)
        self.sock.connect(endpoint)

    def send_data(self, data):
        """Send data to the remote endpoint"""
        self.sock.sendall(data)
        self.sock.close()


def client_handler(args):
    client = VsockStream()
    endpoint = (args.cid, args.port)
    client.connect(endpoint)
    msg = 'Hello, world!'
    client.send_data(msg.encode())


class VsockListener:
    """Server"""
    def __init__(self, conn_backlog=128):
        self.conn_backlog = conn_backlog

    def bind(self, port):
        """Bind and listen for connections on the specified port"""
        self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        self.sock.bind((socket.VMADDR_CID_ANY, port))
        self.sock.listen(self.conn_backlog)

    def recv_data(self):
        """Receive data from a remote endpoint"""
        while True:
            (from_client, (remote_cid, remote_port)) = self.sock.accept()
            data = from_client.recv(1024).decode()
            if not data:
                break
            print(data)
            from_client.close()
            return data

app = Flask(__name__)

@app.route('/')
def hello_world():
        return 'Hello World!'
@app.route("/send_data", methods = ['POST'])
def get_employee_record():
    input_data = request.get_json()
    msg = json.dumps(input_data)
    
    client = VsockStream()
    endpoint = (20, 5005)
    client.connect(endpoint)
    client.send_data(msg.encode())
    server = VsockListener()
    server.bind(5005)
    data = server.recv_data()
    return data

if __name__ == "__main__":
        app.run()