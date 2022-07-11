#!/usr/bin/env python3
import socket
import json
import hashlib
import tqdm
import os
import argparse
from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from colorama import Fore, Back, Style

class Client(object):
    def __init__(self):
        self.HOST = '127.0.0.1'
        self.SERVER = socket.gethostbyname(socket.gethostname())
        self.PORT = 8001
        self.key = b'\xc36g\x00\xcco\x90\xb1b\x93\xb2\xdd\xf9-\xbb\x0c'
        self.BLOCKSIZE = 1024 * 5   # 5KB
        self.AES_BLOCKSIZE = 16
        self.HashValue = b''
        self.cipher = AES.new(self.key, AES.MODE_CTR)
        self.filename = ''
        self.nonce = ''
        self.filesize = 0
        self.SEPARATOR = "<SEPARATOR>"
        self.saved_hash = '931f09f3f0a257682ed5b97492972c520478625e' #for testing later implement better


    def hash(self, file):# https://www.pythoncentral.io/hashing-files-with-python/
        hasher = hashlib.sha1()
        with open(file, 'rb') as afile:
            buf = afile.read(self.BLOCKSIZE)
            while (len(buf) > 0):
                hasher.update(buf)
                buf = afile.read(self.BLOCKSIZE)
        self.HashValue = hasher.hexdigest()      
        print(Fore.LIGHTCYAN_EX + "\nHash:\t" + hasher.hexdigest())


    def compare_hash(self, hashV, server_socket):
        print("Server hash:\t", hashV)
        print("Client hash:\t", self.HashValue)
        if hashV == self.HashValue:
            print("File untampered")
            server_socket.sendall(b'True')
        else:
            print("WARNING: File has been tampered with")


    def encrypt_data(self, file):
        plain_txt = open(file, 'rb')
        with open('ciphertext.txt', 'wb') as cipher_txt:
            byte = plain_txt.read(16)
            while byte:
                ct_bytes = self.cipher.encrypt(byte)
                self.nonce = b64encode(self.cipher.nonce).decode('utf-8')
                cipher_txt.write(ct_bytes)
                byte = plain_txt.read(16)

    def decrypt_data(self, byteData, filename):
        plaintext_txt = open(filename,'w') # write plaintxt
        with open('ciphertext.txt', 'wb') as Wcipher_txt:
            Wcipher_txt.write(byteData)
            Wcipher_txt.close()
            with open('ciphertext.txt', 'rb') as cipher_txt: # read the chiper
                nonce = b64decode(self.nonce)
                d_cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
                byte = cipher_txt.read(16)
                while byte:
                    pt = d_cipher.decrypt(byte)
                    txt = pt.decode("utf-8")
                    plaintext_txt.write(txt)
                    byte = cipher_txt.read(16)

    def send_file(self, filename, socket):
        progress = tqdm.tqdm(range(self.filesize), f"Sending..{filename}", unit="B",
        unit_scale=True, unit_divisor=1024)
        with open(filename, "rb") as sendfile:
            # while True:
            bytes_read = sendfile.read(self.filesize)
            print("FILE TRANSFER COMPLETE: ", len(bytes_read))
            socket.sendall(bytes_read)
            progress.update(len(bytes_read))
            progress.display()
            progress.close()

    def download_from_server(self):
        print(Fore.LIGHTCYAN_EX + "\n[Connecting to Server....]")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.HOST, self.PORT))
            s.sendall(b'recv')
            data = s.recv(12)
            print('[Connection Status]: ', data.decode())

            self.filename = 'data.txt'
            s.sendall( f"{self.filename}{self.SEPARATOR}{self.saved_hash}".encode())

            file_info = s.recv(128).decode()
            filesize, hashIN, self.nonce = file_info.split(self.SEPARATOR)
            self.filesize = int(filesize)
            print("FILESIZE IN:\t", self.filesize)
            print("HASH IN:\t", hashIN)
            s.sendall(b'Packaging') ######
            while True:
                byte = s.recv(self.filesize)
                if len(byte) <= self.filesize:
                    print("TOTAL RECIEVED:\t",self.filesize)
                    break
            self.decrypt_data(byte, self.filename)
            self.hash(self.filename)
            self.compare_hash(hashIN, s)

    
    def upload_to_server(self, filename):
        print("[Connecting to Server....]")
        self.filesize = os.path.getsize(filename)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.HOST, self.PORT))
            s.sendall(b'send')
            data = s.recv(16)
            print('[Connection Status]: ', data.decode())

            s.sendall(
            f"{filename}{self.SEPARATOR}{self.filesize}{self.SEPARATOR}{self.HashValue}{self.SEPARATOR}{self.nonce}".encode())
            data = s.recv(16)
            print(data.decode())
            self.send_file('ciphertext.txt', s)

            data = s.recv(16).decode()
            print("FILE DELETED: ", data)
            # If true then the server sent a conformation message to client so client can delete
            if(data == "True"):
                self.delete_file(file="data.txt")


    def delete_file(self, file):
        if os.path.exists(file):
            os.remove(file)
        else:
            print("File does not exist****")


#######################################################################
#                       Sending file to server
#######################################################################
if __name__ == "__main__":
    test = Client()
    ans = True
    while ans:
        print(Fore.GREEN + "\n############################################")
        print(Fore.LIGHTBLUE_EX + """ 
        1.Upload file to the server
        2.Download a file from the server
        3.Exit/Quit
        """)
        ans = input("What would you like to do? ")
        if ans=="1":
            file = "data.txt"
            test.hash(file)
            test.encrypt_data(file)
            test.upload_to_server(file)
            ans = False
        elif ans=="2":
            test.download_from_server()
            ans = False
        elif ans=="3":
            print(Fore.LIGHTYELLOW_EX + "\n Goodbye")
            ans = False

        elif ans !="":
            print(Fore.YELLOW + "\n NOT A VALID CHOICE TRY AGAIN")
        print(Fore.GREEN + "\n############################################")