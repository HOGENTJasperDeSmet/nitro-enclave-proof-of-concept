
import argparse
import socket
import sys
import rsa as rsa_base
import json
from types import SimpleNamespace
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.interfaces import RSABackend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

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
            command = json.loads(data, object_hook=lambda d: SimpleNamespace(**d))
            handle_command(command)


def handle_command(command):
    if command.command == "GetPublicKey":
        (pubkey, privkey) = load_rsa_keys()
        x = {
            "pubkey": pubkey,
            "message": "ivebeentroughtheenclave"
        }
        client = VsockStream()
        endpoint = (3, 5005)
        client.connect(endpoint)
        msg = json.dumps(x)
        client.send_data(msg.encode())
    

def load_rsa_keys():
    with open('my_public_key.pem', 'rb') as f:
        pubkey = rsa.PublicKey.load_pkcs1(f.read())
    with open('my_private_key.pem', 'rb') as f:
        privkey = rsa.PrivateKey.load_pkcs1(f.read())
    return (pubkey, privkey)

def main():
    parser = argparse.ArgumentParser(prog='vsock-enclave-bp')
    parser.add_argument("--version", action="version",
                        help="Prints version information.",
                        version='%(prog)s 0.1.0')

    parser.add_argument("cid", type=int, help="The remote endpoint CID.")
    parser.add_argument("port", type=int, help="The remote endpoint port.")
    parser.add_argument("port_out", type=int, help="The remote endpoint port.")

    if len(sys.argv) < 2:
        parser.print_usage()
        sys.exit(1)
    args = parser.parse_args()
    (pub, priv) = load_rsa_keys();
    print("hello")
    print(pub)
    
    server = VsockListener()
    server.bind(args.port)
    server.recv_data()




if __name__ == "__main__":
    main()



