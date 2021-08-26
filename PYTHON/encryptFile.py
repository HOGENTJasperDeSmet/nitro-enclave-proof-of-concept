import base64
import logging
import boto3
from botocore.exceptions import ClientError
from cryptography.fernet import Fernet
import requests
import json

NUM_BYTES_FOR_LEN = 4

def create_data_key(cmk_arn, key_spec='AES_256'):

    kms_client = boto3.client('kms')
    response = kms_client.generate_data_key(KeyId=cmk_arn, KeySpec=key_spec)

    return response['CiphertextBlob'], base64.b64encode(response['Plaintext'])

def encrypt_file(filename, cmk_arn):


    with open(filename, 'rb') as file:
        file_contents = file.read()
    
    data_key_encrypted, data_key_plaintext = create_data_key(cmk_arn)
    f = Fernet(data_key_plaintext)
    file_contents_encrypted = f.encrypt(file_contents)

    x = {
        "fileContentsEncrypted": base64.b64encode(file_contents_encrypted).decode(),
        "dataKeyEncrypted": base64.b64encode(data_key_encrypted).decode()
    }


    with open(filename + '.encrypted', 'wb') as file_encrypted:
        file_encrypted.write(len(data_key_encrypted).to_bytes(NUM_BYTES_FOR_LEN,
                                                                  byteorder='big'))
        file_encrypted.write(data_key_encrypted)
        file_encrypted.write(file_contents_encrypted)

    return json.dumps(x)

def decrypt_data_key(data_key_encrypted):


    kms_client = boto3.client('kms')
  
    response = kms_client.decrypt(CiphertextBlob=data_key_encrypted)

    return base64.b64encode((response['Plaintext']))

def decrypt_file_modified(file):
    file = json.loads(file)
    data_key_encrypted = file["dataKeyEncrypted"]
    data_key_encrypted = base64.b64decode(data_key_encrypted)

    data_key_plaintext = decrypt_data_key(data_key_encrypted)
    file_contents_encrypted =  base64.b64decode(file["fileContentsEncrypted"])
    f = Fernet(data_key_plaintext)
    file_contents_decrypted = f.decrypt(file_contents_encrypted)

    
    with open("data.csv", 'wb') as file_decrypted:
        file_decrypted.write(file_contents_decrypted)
    



def decrypt_file(filename):

    try:
        with open(filename + '.encrypted', 'rb') as file:
            file_contents = file.read()
    except IOError as e:
        logging.error(e)
        return False
    data_key_encrypted_len = int.from_bytes(file_contents[:NUM_BYTES_FOR_LEN],
                                            byteorder='big') \
                             + NUM_BYTES_FOR_LEN
    data_key_encrypted = file_contents[NUM_BYTES_FOR_LEN:data_key_encrypted_len]
    
    data_key_plaintext = decrypt_data_key(data_key_encrypted)
    if data_key_plaintext is None:
        logging.error("Cannot decrypt the data key")
        return False

    f = Fernet(data_key_plaintext)
    file_contents_decrypted = f.decrypt(file_contents[data_key_encrypted_len:])

    # Write the decrypted file contents
    try:
        with open(filename + '.decrypted', 'wb') as file_decrypted:
            file_decrypted.write(file_contents_decrypted)
    except IOError as e:
        logging.error(e)
        return False

    return True

def main():
    file_to_encrypt = 'sampledata.csv'

    cmk_arn = "ARN GOES HERE"
    url = 'http://URL GOES HERE/send_data'

    json = encrypt_file(file_to_encrypt,cmk_arn)
    print("File encrypted")


    x = requests.post(url, json=json)
    print(x.text)
    with open("result.csv", 'wb') as file_decrypted:
        file_decrypted.write(x.text)


if __name__ == '__main__':
    main()
