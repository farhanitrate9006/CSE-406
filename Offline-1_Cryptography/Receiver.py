from KeyGeneration import decryptReq
from DiffieHellman import *
import socket

port = 5073
receiveBits = 10 * 1024

# Create a socket object
s = socket.socket()		
# connect to the server on local computer
s.connect(('127.0.0.1', port))

print("Connected to server")

# receive data from the server and decoding to get the string.
p = int(s.recv(receiveBits).decode())
# print("p: ", p)
g = int(s.recv(receiveBits).decode())
# print("g: ", g)
A = int(s.recv(receiveBits).decode())
# print("A: ", A)

b = generatePrivateKeys(p.bit_length())
B = generatePublicKeys(p, g, b)

s.send(str(B).encode())

sharedKey = generateSharedKey(p, A, b)
# key = "BUET CSE18 "

print (s.recv(receiveBits).decode()) # ready to send msg
s.send("Ready to receive".encode())

cipherText = s.recv(receiveBits).decode()
print("Cipher Text: ", cipherText)
plainText = decryptReq(cipherText, sharedKey)
# plainText = decryptReq(cipherText, key)
print("Plain text: ", plainText)
# close the connection
s.close()