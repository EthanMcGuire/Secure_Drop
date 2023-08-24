"""
Functions for security implementations in SecureDrop application.
"""
from datetime import datetime, timedelta
from os import urandom
import random

import bcrypt
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from OpenSSL import crypto

PUBLIC_KEY = "public_key.pem"
PRIVATE_KEY = "private_key.pem"
CA_CERT = "CA.pem"
CA_KEY = "CA_key.pem"
CSR_NAME = "certificate.csr"
CERT_NAME = "certificate.pem"
RSA_KEY_LENGTH_BITS = 2048
SHARED_KEY_LENGTH_BYTES = 16


def hash(string):
    """
    Hash the given string.

    :param string: Text string.
    :return: Hashed string.
    """
    # Encode the string to byte format.
    string = string.encode()

    # Salt and hash the string.
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(string, salt)

    # Decode the hashed string to string format.
    hashed = hashed.decode()

    return hashed


def check_hashed_string(string, hashed_string):
    """
    Check string against hashed string.

    :param string: string input.
    :param hashed_string: Hashed string extracted from file.
    :return: True if string is the same as hashed string, false otherwise.
    """
    # Encode the strings to byte format.
    string = string.encode()
    hashed_string = hashed_string.encode()

    # Check that the string matches the hashed string.
    if bcrypt.checkpw(string, hashed_string):
        return True

    return False


def generate_keys():
    """
    Generate and save public and private keys for the user.

    :return: None
    """
    private_key = RSA.generate(RSA_KEY_LENGTH_BITS)
    public_key = private_key.public_key()

    with open(PRIVATE_KEY, "wb") as f:
        f.write(private_key.export_key())

    with open(PUBLIC_KEY, "wb") as f:
        f.write(public_key.export_key())


def encrypt_file(data, file):
    """
    Encrypt data and write to file.

    :param data: Data to encrypt.
    :param file: File to write encrypted data.
    :return: None
    """
    # Convert data to byte format.
    data_bytes = data.encode()

    # Generate random shared key.
    shared_key = urandom(SHARED_KEY_LENGTH_BYTES)

    # Encrypt data using shared key.
    aes_enc_obj = AES.new(shared_key, AES.MODE_GCM)
    ciphertext, tag = aes_enc_obj.encrypt_and_digest(data_bytes)
    nonce = aes_enc_obj.nonce

    # Acquire user's public key.
    with open(PUBLIC_KEY, "r") as f:
        public_key = RSA.import_key(f.read())

    # Encrypt key with public key.
    rsa_enc_obj = PKCS1_OAEP.new(public_key)
    enc_shared_key = rsa_enc_obj.encrypt(shared_key)

    # Write encrypted data to file.
    encrypted_data = enc_shared_key + tag + nonce + ciphertext
    with open(file, "wb") as f:
        f.write(encrypted_data)


def decrypt_file(file):
    """
    Decrypt file and retrieve data.

    :param file: File to decrypt.
    :return: Decrypted data from file.
    """
    # Retrieve encrypted information from file.
    with open(file, "rb") as f:
        enc_shared_key = f.read(int(RSA_KEY_LENGTH_BITS / 8))
        tag = f.read(SHARED_KEY_LENGTH_BYTES)
        nonce = f.read(SHARED_KEY_LENGTH_BYTES)
        ciphertext = f.read()

    # Acquire user's private key.
    with open(PRIVATE_KEY, "r") as f:
        private_key = RSA.import_key(f.read())

    # Decrypt key with private key.
    rsa_dec_obj = PKCS1_OAEP.new(private_key)
    dec_shared_key = rsa_dec_obj.decrypt(enc_shared_key)

    # Decrypt and verify integrity of the ciphertext.
    aes_dec_obj = AES.new(dec_shared_key, AES.MODE_GCM, nonce=nonce)
    decrypted_data = aes_dec_obj.decrypt_and_verify(ciphertext, tag)

    # Decode decrypted data to string format.
    return decrypted_data.decode()


def create_certificate():
    """
    Create a digital certificate signed by a certificate authority.

    :return: None
    """
    # Acquire user's public and private keys.
    with open(PUBLIC_KEY, "rb") as f:
        public_key = crypto.load_publickey(crypto.FILETYPE_PEM, f.read())
    with open(PRIVATE_KEY, "rb") as f:
        private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

    # Generate certificate signing request.
    csr = crypto.X509Req()
    csr.get_subject().CN = "localhost"
    csr.get_subject().C = "US"
    csr.get_subject().ST = "Massachusetts"
    csr.get_subject().L = "Lowell"
    csr.get_subject().O = "UML"
    csr.get_subject().OU = "UG"

    # Set CSR's public key to user's public key.
    csr.set_pubkey(public_key)
    # Sign CSR with user's private key.
    csr.sign(private_key, "sha256")

    # Acquire CA root certificate and private key.
    with open(CA_CERT, "rb") as f:
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    with open(CA_KEY, "rb") as f:
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

    # Generate CA-signed client certificate.
    cert = crypto.X509()
    cert.set_version(1)
    cert.set_serial_number(random.randint(0,10000000))
    cert.set_issuer(ca_cert.get_subject())
    cert.set_subject(csr.get_subject())
    cert.set_pubkey(csr.get_pubkey())
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(2592000) # Certificate is valid for 30 days.
    cert.sign(ca_key, "sha256")

    # Save user certificate.
    # The user's certificate is chained with the CA's root certificate.
    with open(CERT_NAME, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))
