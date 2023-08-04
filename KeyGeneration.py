from BitvectorDemo import *
import time

plainText = "Can They Do This something more"
key = "BUET CSE18 "
roundNumConstant = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
allWords = list()
totalRounds = 10
matrixDim = 4
LENGTH = 16

stateMat = [[0 for _ in range(matrixDim)] for _ in range(matrixDim)]
keyMat = [[0 for _ in range(matrixDim)] for _ in range(matrixDim)]

# convert ascii to int
def textInit():
    global plainText
    plainText = int.from_bytes(plainText.encode(), byteorder='big')

def keyInit():
    global key
    key = int.from_bytes(key.encode(), byteorder='big')

def getWord(num, i):
    return ((num & ((1 << 32*(4-i)) - 1)) >> 32*(3-i))

def getFourWords(num):
    words = list()
    for i in range(4):
        words.append(getWord(num, i))
    return words

def byteLeftShiftCircular(word):
    word = (((word << 8) | (word >> 24)) & 0xffffffff)
    return word

def sboxSubstitution(byte, inverse:bool):
    b = BitVector(intVal=byte, size=32)
    int_val = b.intValue()
    s = InvSbox[int_val] if inverse else Sbox[int_val]
    s = BitVector(intVal=s, size=8)
    return s.intValue()

def getByte(word, i):
    rightShiftedByte = (word >> (8*i))
    actualByte = rightShiftedByte & 0xff
    return actualByte

def byteSubstitution(word):
    for i in range(4):
        byte = getByte(word, i)
        word = word & ~(0xff << (8*i))
        word = word | (sboxSubstitution(byte, inverse=False) << (8*i))
    return word

def addRoundConstant(word, roundNum):
    word = word ^ (roundNumConstant[roundNum-1] << 24)
    return word

def changeRightmostWord(word, roundNum):
    word = byteLeftShiftCircular(word)
    word = byteSubstitution(word)
    word = addRoundConstant(word, roundNum)
    return word

def genRoundKey(roundNum):
    roundNumToUse = roundNum-1
    allWords.append(allWords[roundNumToUse*4] ^ changeRightmostWord(allWords[roundNum*4 - 1], roundNum))
    for i in range(3):
        allWords.append(allWords[roundNumToUse*4 + i + 1] ^ allWords[roundNum*4 + i])

def genAllRoundKeys(key:str):
    words = getFourWords(key)
    allWords.extend(words)

    for roundNum in range(1, totalRounds+1):
        genRoundKey(roundNum)

def fillMat(words, matrix):
    for i in range(matrixDim):
        for j in range(matrixDim):
            matrix[j][i] = getByte(words[i], 3-j)

def substituteMat(inverse:bool):
    for i in range(matrixDim):
        for j in range(matrixDim):
            stateMat[i][j] = sboxSubstitution(stateMat[i][j], inverse)

def leftShiftMatRowCircular(row):
    for _ in range(row):
        temp = stateMat[row][0]
        for i in range(matrixDim-1):
            stateMat[row][i] = stateMat[row][i+1]
        stateMat[row][matrixDim-1] = temp

def rightShiftMatRowCircular(row):
    for _ in range(row):
        temp = stateMat[row][matrixDim-1]
        for i in range(matrixDim-1, 0, -1):
            stateMat[row][i] = stateMat[row][i-1]
        stateMat[row][0] = temp

def shiftMat():
    for row in range(1, matrixDim):
        leftShiftMatRowCircular(row)

def invShiftMat():
    for row in range(1, matrixDim):
        rightShiftMatRowCircular(row)

def specialMultiply(a, b):
    b = BitVector(hexstring=b)
    return a.gf_multiply_modular(b, AES_modulus, 8).intValue()

def mixColumns(inverse:bool):
    global stateMat
    resultMat = [[0 for _ in range(matrixDim)] for _ in range(matrixDim)]

    # iterate through rows of X
    for i in range(matrixDim):
    # iterate through columns of Y
        for j in range(matrixDim):
            # iterate through rows of Y
            for k in range(matrixDim):
                firstParam = Mixer[i][k] if not inverse else InvMixer[i][k]
                secondParam = hex(stateMat[k][j])[2:4]
                resultMat[i][j] ^= specialMultiply(firstParam, secondParam)

    stateMat = resultMat

def addRoundKey(start:int):
    fillMat(allWords[start:start + 4], keyMat)
    for i in range(matrixDim):
        for j in range(matrixDim):
            stateMat[i][j] = stateMat[i][j] ^ keyMat[i][j]

def encryptionRound(roundNum):
    if roundNum != 0:
        substituteMat(inverse=False)
        shiftMat()
        if roundNum != totalRounds:
            mixColumns(inverse=False)
    
    addRoundKey(start=roundNum*4)

def decryptionRound(roundNum):
    if roundNum != 0:
        invShiftMat()
        substituteMat(inverse=True)
    addRoundKey(start=(10 - roundNum)*4)
    if roundNum != 0 and roundNum != totalRounds:
        mixColumns(inverse=True)

def printStateMat():
    print("State Matrix: ")
    for i in range(matrixDim):
        for j in range(matrixDim):
            print(hex(stateMat[i][j]), end=" ")
        print()

def convertMatToHex():
    hexString = ""
    for i in range(matrixDim):
        for j in range(matrixDim):
            hexForm = hex(stateMat[j][i])[2:4]
            if len(hexForm) == 1:
                hexForm = "0" + hexForm
            hexString += hexForm
    return hexString

# convert int to ascii
def fixKey(key: int) -> str:
    key = hex(key)[2:]
    # key = key.zfill(32)
    if len(key) > LENGTH:
        key = key[:LENGTH]
    else:
        key = key.ljust(LENGTH, '\0')
    return key

def encryptReq(plainText: str, key) -> str:
    if key.__class__.__name__ == "str":
        key = int.from_bytes(key.encode(), byteorder='big')
    key = int(fixKey(key), 16) # int => 16 bytes ascii => int

    iterations = len(plainText) // LENGTH
    encryptedText = ""

    for i in range(iterations):
        start = i*LENGTH
        end = (i+1)*LENGTH
        encryptedText += encryption(plainText[start:end], key)

    if len(plainText) % LENGTH:
        lastChunk = plainText[iterations*LENGTH:]
        lastChunk = lastChunk.ljust(LENGTH, '\0')
        encryptedText += encryption(lastChunk, key)

    return encryptedText

def encryption(plainText: str, key: int) -> str:
    plainText = int.from_bytes(plainText.encode(), byteorder='big')

    genAllRoundKeys(key)
    fillMat(getFourWords(plainText), stateMat)

    for roundNum in range(totalRounds+1):
        encryptionRound(roundNum) 

    encryptedTextInHex = convertMatToHex()
    encryptedText = BitVector(hexstring=encryptedTextInHex).get_bitvector_in_ascii()

    return encryptedText

def decryptReq(cipherText: str, key) -> str:
    if key.__class__.__name__ == "str":
        key = int.from_bytes(key.encode(), byteorder='big')
    key = int(fixKey(key), 16) # int => 16 bytes ascii => int

    iterations = len(cipherText) // LENGTH
    decryptedText = ""

    for i in range(iterations):
        start = i*LENGTH
        end = (i+1)*LENGTH
        decryptedText += decryption(cipherText[start:end], key)

    if len(cipherText) % LENGTH:
        lastChunk = cipherText[iterations*LENGTH:]
        lastChunk = lastChunk.ljust(LENGTH, '\0')
        decryptedText += decryption(lastChunk, key)

    return decryptedText

def decryption(cipherText: str, key: int) -> str:
    cipherText = int(BitVector(textstring=cipherText).get_bitvector_in_hex(), 16)

    genAllRoundKeys(key)
    fillMat(getFourWords(cipherText), stateMat)

    for roundNum in range(totalRounds+1):
        decryptionRound(roundNum) 

    decipheredTextInHex = convertMatToHex()
    decipheredText = BitVector(hexstring=decipheredTextInHex).get_bitvector_in_ascii().rstrip('\0')

    return decipheredText

if __name__ == "__main__":
    print("Plain Text:")
    print("In ASCII: ", plainText)
    textInit()
    print("In HEX: ", hex(plainText)[2:])
    print()

    print("Key:")
    print("In ASCII: ", key)
    keyInit()
    print("In HEX: ", hex(key)[2:])
    print()

    keySchedulingStart = time.time()
    genAllRoundKeys(key)
    keySchedulingEnd = time.time()
    keySchedulingTime = keySchedulingEnd - keySchedulingStart

    encryptionStart = time.time()
    fillMat(getFourWords(plainText), stateMat)
    for roundNum in range(totalRounds+1):
        encryptionRound(roundNum)
    encryptionEnd = time.time()
    encryptionTime = encryptionEnd - encryptionStart 
    encryptedTextInHex = convertMatToHex()
    print("Cipher Text:")
    print("In HEX: ", encryptedTextInHex)
    encryptedText = BitVector(hexstring=encryptedTextInHex).get_bitvector_in_ascii()
    print("In ASCII: ", encryptedText)
    print()

    decryptionStart = time.time()
    for roundNum in range(totalRounds+1):
        decryptionRound(roundNum)
    decryptionEnd = time.time()
    decryptionTime = decryptionEnd - decryptionStart
    decipheredTextInHex = convertMatToHex()
    print("Deciphered Text:")
    print("In HEX: ", decipheredTextInHex)
    decipheredText = BitVector(hexstring=decipheredTextInHex).get_bitvector_in_ascii()
    print("In ASCII: ", decipheredText)
    print()

    print("Execution time details:")
    print("Key Scheduling: ", keySchedulingTime, " seconds")
    print("Encryption Time: ", encryptionTime, " seconds")
    print("Decryption Time: ", decryptionTime, " seconds")