import boto3
import json
import base64
import socket
import subprocess

from cryptography.fernet import Fernet


KMS_PROXY_PORT="8000"

def get_plaintext(credentials):
    access = credentials['access_key_id']
    secret = credentials['secret_access_key']
    token = credentials['token']
    region = credentials['region']
    test = json.loads(json.loads(credentials['ciphertext']))

    data_key_encrypted = test["dataKeyEncrypted"]
    creds = decrypt_cipher(access, secret, token, data_key_encrypted, region)
    return creds

def decrypt_file_modified(file, key):
    file = json.loads(json.loads(file))

    file_contents_encrypted =  base64.b64decode(file["fileContentsEncrypted"])
    f = Fernet(key)
    file_contents_decrypted = f.decrypt(file_contents_encrypted)
    
    with open("data.csv", 'wb') as file_decrypted:
        file_decrypted.write(file_contents_decrypted)
        
    return file_contents_decrypted.decode()

def decrypt_cipher(access, secret, token, ciphertext, region):
    proc = subprocess.Popen(
    [
        "/app/kmstool_enclave_cli",
        "--region", region,
        "--proxy-port", KMS_PROXY_PORT,
        "--aws-access-key-id", access,
        "--aws-secret-access-key", secret,
        "--aws-session-token", token,
        "--ciphertext", ciphertext,
    ],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

    ret = proc.communicate()

    if ret[0]:
        b64text = proc.communicate()[0].decode()
        return b64text
    else:
        return "KMS Error. Decryption Failed."


def main():


    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    cid = socket.VMADDR_CID_ANY
    port = 5000
    s.bind((cid, port))
    s.listen()
    print(f"Started server on port {port} and cid {cid}")

    while True:
        c, addr = s.accept()
        payload = c.recv(4096)
        r = {}
        credentials = json.loads(payload.decode())
        
        key = get_plaintext(credentials)
    
        x = decrypt_file_modified(credentials['ciphertext'],key)
        
        
        #Pandas laat importeren om /dev/rand eerst optevullen
        import pandas as pd
        data = pd.read_csv("data.csv") 
        print(data.head())
        data = data.drop(columns="first name")
        print(data.head())
        
        print(data.to_csv())
        print(type(data.to_csv()))
        
        c.send(str.encode(data.to_csv()))

        c.close()

if __name__ == '__main__':
    main()
