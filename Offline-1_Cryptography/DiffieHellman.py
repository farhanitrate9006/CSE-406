from DH_Util import *
import time

iterationForPrime = 5

# func to calc p
def generatePublicModulus(k: int):
    q = 1 << (k-2)
    while True:
        p = 2*q + 1
        if isPrime(p, iterationForPrime) and isPrime(q, iterationForPrime):
            return p
        q += 1

def testPublicBase(p: int, g: int):
    return g > 2 and g < p-1 and modularExp(g, (p-1)//2, p) != 1

# func to calc g
def generatePublicBase(p: int, min: int, max: int):
    while True:
        g = random.randint(min, max)
        if testPublicBase(p, g):
            return g

# func to calc a, b        
def generatePrivateKeys(k: int):
    min = 1 << (k//2 - 1)
    max = 1 << (k-1)
    while True:
        privateKey = random.randint(min, max)
        if isPrime(privateKey, iterationForPrime):
            return privateKey

# func to calc A, B
def generatePublicKeys(p: int, g: int, privateKey: int):
    return modularExp(g, privateKey, p)

# func to calc A^b, B^a
def generateSharedKey(p: int, publicKey: int, privateKey: int):
    return modularExp(publicKey, privateKey, p)

def generateAll(k: int):
    pStart = time.time()
    p = generatePublicModulus(k)
    pEnd = time.time()
    pTime = pEnd - pStart
    # print("Time for p: ", pTime)

    gStart = time.time()
    min = 2
    max = p-2
    g = generatePublicBase(p, min, max)
    gEnd = time.time()
    gTime = gEnd - gStart
    # print("Time for g: ", gTime)

    aStart = time.time()
    a = generatePrivateKeys(k)
    aEnd = time.time()
    aTime = aEnd - aStart
    # print("Time for a: ", aTime)
    b = generatePrivateKeys(k)

    AStart = time.time()
    A = generatePublicKeys(p, g, a)
    AEnd = time.time()
    ATime = AEnd - AStart
    # print("Time for A: ", ATime)
    B = generatePublicKeys(p, g, b)

    sharedKeyStart = time.time()
    sharedKey1 = generateSharedKey(p, A, b)
    sharedKeyEnd = time.time()
    sharedKeyTime = sharedKeyEnd - sharedKeyStart
    # print("Time for shared key: ", sharedKeyTime)
    sharedKey2 = generateSharedKey(p, B, a)

    # return pTime, gTime, aTime, ATime, sharedKeyTime
    return p, g, a, A, b, B, sharedKey1, sharedKey2


if __name__ == "__main__":
    keySizeStart = 128
    keySizeEnd = 256
    increment = 64
    trials = 5

    # for k in range(keySizeStart, keySizeEnd + 1, increment):
    #     print("For k: ", k)
    #     pSum = gSum = aSum = ASum = sharedKeySum = 0

    #     for j in range(trials):
    #         pTime, gTime, aTime, ATime, sharedKeyTime = generateAll(k)
    #         pSum += pTime
    #         gSum += gTime
    #         aSum += aTime
    #         ASum += ATime
    #         sharedKeySum += sharedKeyTime

    #     print("Time for p: ", pSum/trials)
    #     print("Time for g: ", gSum/trials)
    #     print("Time for a: ", aSum/trials)
    #     print("Time for A: ", ASum/trials)
    #     print("Time for shared key: ", sharedKeySum/trials)

    #     print()
    p, g, a, A, b, B, sharedKey1, sharedKey2 = generateAll(keySizeStart)
    print("p: ", p)
    print("g: ", g)
    print("a: ", a)
    print("b: ", b)
    print("A: ", A)
    print("B: ", B)
    print("sharedKey1: ", sharedKey1)
    print("sharedKey2: ", sharedKey1)

