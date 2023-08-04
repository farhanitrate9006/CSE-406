from DiffieHellman import *
from KeyGeneration import encryptReq
import socket

port = 5073
receiveBits = 10 * 1024

# next create a socket object
s = socket.socket()		
print ("Socket successfully created")		
s.bind(('', port))		
print ("socket binded to %s" %(port))
s.listen(5)	
print ("socket is listening")

def generateNecesarries(k: int):
    p = generatePublicModulus(k)

    min = 2
    max = p-2
    g = generatePublicBase(p, min, max)

    a = generatePrivateKeys(k)
    A = generatePublicKeys(p, g, a)
    return p, g, a, A

# a forever loop until we interrupt it or
# an error occurs
while True:
    # Establish connection with client.
    c, addr = s.accept()	
    print ('Got connection from', addr )

    # keySize = int(input("Enter the key size: "))
    keySize = 128
    p, g, a, A = generateNecesarries(keySize)

    print(p, g, A)

    c.send(str(p).encode())
    print("p sent")
    c.send(str(g).encode())
    print("g sent")
    c.send(str(A).encode())
    print("A sent")

    B = int(c.recv(receiveBits).decode())
    sharedKey = generateSharedKey(p, B, a)
    # key = "BUET CSE18 "

    c.send("Ready to send".encode())
    print (c.recv(receiveBits).decode())

    # text = "Hello World from Sender side of Diffie Hellman Key Exchange"
    text = "Can They Do This something more"
    print("Plain Text: ", text)
    cipherText = encryptReq(text, sharedKey)
    # cipherText = encryptReq(text, key)
    print("Cipher Text: ", cipherText)
    c.send(cipherText.encode())

    # Close the connection with the client
    c.close()

    # Breaking once connection closed
    break
