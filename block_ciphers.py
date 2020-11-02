from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode,b64decode
from Crypto.Util import Counter
import binascii
from hashlib import md5
import os
import time
import json

password="0987654321"
key="1234567890abcdef"
key = md5(key.encode('utf8')).digest()

files_to_encrypt = ['1m.txt', '64m.txt', '128m.txt']

def ctre():
    for file_to_encrypt in files_to_encrypt:
        input_file = open(file_to_encrypt, "rb")
        output_file = open('encrypted' + file_to_encrypt, 'w')
        startd = time.time()
        buffer_size = os.stat(file_to_encrypt).st_size
        data = input_file.read(buffer_size)
        cipher = AES.new(key, AES.MODE_CTR)
        ct_bytes = cipher.encrypt(data)
        nonce = b64encode(cipher.nonce).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps({'nonce':nonce, 'ct':ct})
        output_file.write(result)
        print("CTR encrypt time " + file_to_encrypt)
        endd = time.time()
        print(endd - startd)
def ctrd():
    for file_to_encrypt in files_to_encrypt:
        input_file = open('encrypted' + file_to_encrypt, 'rb')
        output_file = open('decrypted' + file_to_encrypt, 'wb')
        startd = time.time()
        buffer_size = os.stat('encrypted' + file_to_encrypt).st_size
        json_input = input_file.read(buffer_size)
        b64 = json.loads(json_input)
        nonce = b64decode(b64['nonce'])
        ct = b64decode(b64['ct'])
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        pt = cipher.decrypt(ct)
        output_file.write(pt)
        print("CTR decrypt time " + file_to_encrypt)
        endd = time.time()
        print(endd - startd)

def cbce():
    for file_to_encrypt in files_to_encrypt:
        input_file = open(file_to_encrypt, "rb")
        output_file = open('encrypted' + file_to_encrypt, 'w')
        startd = time.time()
        buffer_size = os.stat(file_to_encrypt).st_size
        data = input_file.read(buffer_size)
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps({'iv':iv, 'ct':ct})
        output_file.write(result)
        print("CBC encrypt time " + file_to_encrypt)
        endd = time.time()
        print(endd - startd)
def cbcd():
    for file_to_encrypt in files_to_encrypt:
        input_file = open('encrypted' + file_to_encrypt, 'rb')
        output_file = open('decrypted' + file_to_encrypt, 'wb')
        startd = time.time()
        buffer_size = os.stat('encrypted' + file_to_encrypt).st_size
        json_input = input_file.read(buffer_size)
        b64 = json.loads(json_input)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ct'])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        output_file.write(pt)
        print("CBC decrypt time " + file_to_encrypt)
        endd = time.time()
        print(endd - startd)

def cfbe():
    for file_to_encrypt in files_to_encrypt:
        input_file = open(file_to_encrypt, "rb")
        output_file = open('encrypted' + file_to_encrypt, 'w')
        startd = time.time()
        buffer_size = os.stat(file_to_encrypt).st_size
        data = input_file.read(buffer_size)
        cipher = AES.new(key, AES.MODE_CFB)
        ct_bytes = cipher.encrypt(data)
        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps({'iv': iv, 'ciphertext': ct})
        output_file.write(result)
        print("CFB encrypt time " + file_to_encrypt)
        endd = time.time()
        print(endd - startd)
def cfbd():
    for file_to_encrypt in files_to_encrypt:
        input_file = open('encrypted' + file_to_encrypt, 'rb')
        output_file = open('decrypted' + file_to_encrypt, 'wb')
        startd = time.time()
        buffer_size = os.stat('encrypted' + file_to_encrypt).st_size
        json_input = input_file.read(buffer_size)
        b64 = json.loads(json_input)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        pt = cipher.decrypt(ct)
        output_file.write(pt)
        print("CFB decrypt time " + file_to_encrypt)
        endd = time.time()
        print(endd - startd)


def ofbe():
    for file_to_encrypt in files_to_encrypt:
        input_file = open(file_to_encrypt, "rb")
        output_file = open('encrypted' + file_to_encrypt, 'w')
        startd = time.time()
        buffer_size = os.stat(file_to_encrypt).st_size
        data = input_file.read(buffer_size)
        cipher = AES.new(key, AES.MODE_OFB)
        ct_bytes = cipher.encrypt(data)
        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps({'iv': iv, 'ciphertext': ct})
        output_file.write(result)
        print("OFB encrypt time " + file_to_encrypt)
        endd = time.time()
        print(endd - startd)
def ofbd():
    for file_to_encrypt in files_to_encrypt:
        input_file = open('encrypted' + file_to_encrypt, 'rb')
        output_file = open('decrypted' + file_to_encrypt, 'wb')
        startd = time.time()
        buffer_size = os.stat('encrypted' + file_to_encrypt).st_size
        json_input = input_file.read(buffer_size)
        b64 = json.loads(json_input)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_OFB, iv=iv)
        pt = cipher.decrypt(ct)
        output_file.write(pt)
        print("OFB decrypt time " + file_to_encrypt)
        endd = time.time()
        print(endd - startd)

def ecbe():
    for file_to_encrypt in files_to_encrypt:
        input_file = open(file_to_encrypt, "rb")
        output_file = open('encrypted' + file_to_encrypt, 'w')
        startd = time.time()
        buffer_size = os.stat(file_to_encrypt).st_size
        data = input_file.read(buffer_size)
        cipher = AES.new(key, AES.MODE_ECB)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps({'ct':ct})
        output_file.write(result)
        print("ECB encrypt time " + file_to_encrypt)
        endd = time.time()
        print(endd - startd)
def ecbd():
    for file_to_encrypt in files_to_encrypt:
        input_file = open('encrypted' + file_to_encrypt, 'rb')
        output_file = open('decrypted' + file_to_encrypt, 'wb')
        startd = time.time()
        buffer_size = os.stat('encrypted' + file_to_encrypt).st_size
        json_input = input_file.read(buffer_size)
        b64 = json.loads(json_input)
        ct = b64decode(b64['ct'])
        cipher = AES.new(key, AES.MODE_ECB)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        output_file.write(pt)
        print("ECB decrypt time " + file_to_encrypt)
        endd = time.time()
        print(endd - startd)

