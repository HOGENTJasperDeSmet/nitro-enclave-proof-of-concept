from flask import Flask, request, jsonify
import argparse
import socket
import sys
import json
import requests
import subprocess


def get_identity_document():
    r = requests.get(
        "http://169.254.169.254/latest/dynamic/instance-identity/document")
    return r

def get_region(identity):
    region = identity.json()["region"]
    return region

def get_account(identity):
    region = identity.json()["accountId"]
    return region

def set_identity():
    identity = get_identity_document()
    region = get_region(identity)
    account = get_account(identity)
    return region, account

REGION, ACCOUNT = set_identity()

def prepare_server_request(ciphertext):
    r = requests.get(
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    instance_profile_name = r.text

    r = requests.get(
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/%s" %
        instance_profile_name)
    response = r.json()

    credential = {
        'access_key_id': response['AccessKeyId'],
        'secret_access_key': response['SecretAccessKey'],
        'token': response['Token'],
        'region': REGION,
        'ciphertext': ciphertext
    }

    return credential

def get_cid():
    """
    Determine CID of Current Enclave
    """
    proc = subprocess.Popen(["/bin/nitro-cli", "describe-enclaves"],
                            stdout=subprocess.PIPE)
    output = json.loads(proc.communicate()[0].decode())
    enclave_cid = output[0]["EnclaveCID"]
    return enclave_cid

app = Flask(__name__)
@app.route('/')
def hello_world():
        return 'Succesfull install'
@app.route("/send_data", methods = ['POST'])
def send_data():
    input_data = request.get_json()
    credential = prepare_server_request(json.dumps(input_data))
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)

    # Get CID from command line parameter
    cid = get_cid()
    # The port should match the server running in enclave
    port = 5000
    # Connect to the server
    s.connect((cid, port))
    # Send AWS credential to the server running in enclave
    s.send(str.encode(json.dumps(credential)))
    r = s.recv(1048576).decode()
    # close the connection
    s.close()

    return r

if __name__ == "__main__":
        app.run()
