from DH_Util import *

iterationForPrime = 5

# func to calc p
def generatePublicModulus(k:int):
    q = 1 << (k-2)
    while True:
        p = 2*q + 1
        if isPrime(p, iterationForPrime) and isPrime(q, iterationForPrime):
            return p
        q += 1

def testPublicBase(p:int, g:int):
    return g > 2 and g < p-1 and modularExp(g, (p-1)//2, p) != 1

# func to calc g
def generatePublicBase(p:int, min:int, max:int):
    while True:
        g = random.randint(min, max)
        if testPublicBase(p, g):
            return g

# func to calc a, b        
def generatePrivateKeys(k:int):
    min = 1 << (k//2 - 1)
    max = 1 << (k-1)
    while True:
        privateKey = random.randint(min, max)
        if isPrime(privateKey, iterationForPrime):
            return privateKey
        privateKey += 1

# func to calc A, B
def generatePublicKeys(p:int, g:int, privateKey:int):
    return modularExp(g, privateKey, p)

# func to calc A^b, B^a
def generateSharedKey(p:int, publicKey:int, privateKey:int):
    return modularExp(publicKey, privateKey, p)

if __name__ == "__main__":
    k = 128
    p = generatePublicModulus(k)

    min = 2
    max = p-2
    g = generatePublicBase(p, min, max)

    a = generatePrivateKeys(k)
    b = generatePrivateKeys(k)

    A = generatePublicKeys(p, g, a)
    B = generatePublicKeys(p, g, b)

    sharedKey1 = generateSharedKey(p, A, b)
    sharedKey2 = generateSharedKey(p, B, a)

    print("p:", p)
    print("g:", g)
    print("a:", a)
    print("b:", b)
    print("A:", A)
    print("B:", B)
    print("sharedKey1:", sharedKey1)
    print("sharedKey2:", sharedKey2)

