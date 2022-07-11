#!/usr/bin/env python3
import socket
import sys
import json
import hashlib
import os
import tqdm
from base64 import b64decode
from base64 import b64encode
from Crypto.Cipher import AES
from colorama import Fore, Back, Style

class Server(object):
    def __init__(self):
        self.HOST = '127.0.0.1'
        self.PORT = 8001
        self.key = b'\xc36g\x00\xcco\x90\xb1b\x93\xb2\xdd\xf9-\xbb\x0c'
        self.AES_BLOCKSIZE = 16
        self.BLOCKSIZE = 5628
        self.HashValue = b''
        self.cipher = AES.new(self.key, AES.MODE_CTR)
        self.nonce = ''
        self.filename = ""
        self.filesize = 0
        self.SEPARATOR = "<SEPARATOR>"


    def delete_file(self, file):
        if os.path.exists(file):
            os.remove(file)
        else:
            print("File does not exist****")

########################################################################
########################################################################

    def hash(self, file):
        hasher = hashlib.sha1()
        with open(file, 'rb') as afile:
            buf = afile.read(self.BLOCKSIZE)
            while (len(buf) > 0):
                hasher.update(buf)
                buf = afile.read(self.BLOCKSIZE)
        Server_Hash_Value = hasher.hexdigest() # 40 lenght - <str>
        return Server_Hash_Value


    def compare_sending_hash(self, hashV, client_socket):
        print("\nServer hash:\t", hashV)
        print("Client hash:\t", self.HashValue)
        if hashV == self.HashValue:
            print("FILE NOT CORUPT\n")
            self.encrypt_data(self.filename) 
            self.send_file('ciphertext.txt', client_socket)
        else:
            print("WARNING FILE CORUPT")

    def compare_hash(self, hashV, socket):
        print("\nServer hash:\t", hashV)
        print("Client hash:\t", self.HashValue)
        if hashV == self.HashValue:
            print("File untampered")
            msg = "True"
            socket.sendall(msg.encode())
        else:
            msg = "False"
            socket.sendall(msg.encode())
            print("WARNING: File has been tampered with")


    def encrypt_data(self, file):
        plain_txt = open(file, 'rb')
        with open('ciphertext.txt', 'wb') as cipher_txt:
            byte = plain_txt.read(16)
            while byte:
                ct_bytes = self.cipher.encrypt(byte)
                self.nonce = b64encode(self.cipher.nonce).decode('utf-8') # NOUNCE
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


    def process_out_data(self, client_socket): ############### main client downlaod
        confirm_conn = b'Establilshed'
        client_socket.sendall(confirm_conn)
        file_info = client_socket.recv(128).decode()
        self.filename, self.HashValue = file_info.split(self.SEPARATOR)
        self.filesize = os.path.getsize(self.filename) ## FILE SIZE
        server_hash = self.hash("data.txt") ## HASHVALUE
        self.compare_sending_hash(server_hash, client_socket)  


    def send_file(self, filename, client_socket):
        client_socket.sendall( f"{self.filesize}{self.SEPARATOR}{self.HashValue}{self.SEPARATOR}{self.nonce}".encode())
        print(client_socket.recv(9).decode()) #####

        progress = tqdm.tqdm(range(self.filesize), f"Sending..{filename}", unit="B",
        unit_scale=True, unit_divisor=1024)

        with open(filename, "rb") as sendfile:
            bytes_read = sendfile.read(self.filesize)
            client_socket.sendall(bytes_read)
            progress.update(len(bytes_read))
            progress.display()
            progress.close()

        data = client_socket.recv(4).decode()
        print("FILE DELETED FROM SERVER: ", data)
        # If true then the server sent a conformation message to client so client can delete
        if(data == "True"):
            self.delete_file(file="data.txt")      

#######################################################################################        
#######################################################################################

    def process_in_data(self, client_socket):
        confirm_conn = b'Establilshed'
        client_socket.sendall(confirm_conn)
        file_info = client_socket.recv(128).decode()
        self.filename, filesize, self.HashValue, self.nonce = file_info.split(self.SEPARATOR)
        self.filename = os.path.basename(self.filename)
        self.filesize = int(filesize)
        client_socket.sendall(b'\nEncrypting...')
        while True:
            byte = client_socket.recv(self.filesize)
            if len(byte) <= self.filesize:
                break
        self.decrypt_data(byte, self.filename)
        server_hash = self.hash(self.filename)
        self.compare_hash(server_hash, client_socket)      

        
    def connect_from_client(self):
        print(Fore.LIGHTCYAN_EX + "[Listening....]")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.HOST,self.PORT))
            s.listen()
            conn, addr = s.accept()                   
            with conn: 
                # maybe a while function to end the conn when the client wants             
                print('[Connected by:\t', addr , ']') 
                data = conn.recv(self.BLOCKSIZE).decode()
                ## true or false 
                if data == "send":
                    print("************  Receiving File File From Client  ***************")
                    self.process_in_data(conn)
                elif data == "recv":
                    print("************  Sending File to Client  ************")
                    self.process_out_data(conn)


test = Server()
test.connect_from_client()
print('\nALL DONE')