from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def encrypt(plaintext, key):
    encryptor = PKCS1_OAEP.new(key)
    encrypted_msg = encryptor.encrypt(plaintext)
    return encrypted_msg

def decrypt(ciphertext, key):
    decryptor = PKCS1_OAEP.new(key)
    decrypted_msg = decryptor.decrypt(ciphertext)
    return decrypted_msg

def read_key(key_path):
    with open(key_path, 'r') as key_file:
        key = RSA.import_key(key_file.read())
        return key