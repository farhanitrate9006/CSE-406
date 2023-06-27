from BitvectorDemo import *

key = "Thats my Kung Fu"
plainText = "Two One Nine Two"
roundNumConstant = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
allWords = list()
totalRounds = 10
matrixDim = 4
# AES_modulus = BitVector(bitstring='100011011')

stateMat = [[0 for _ in range(matrixDim)] for _ in range(matrixDim)]
keyMat = [[0 for _ in range(matrixDim)] for _ in range(matrixDim)]

# convert key to 128 bit binary
key = int.from_bytes(key.encode(), byteorder='big')
plainText = int.from_bytes(plainText.encode(), byteorder='big')

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

def sboxSubstitution(byte):
    b = BitVector(intVal=byte, size=32)
    int_val = b.intValue()
    s = Sbox[int_val]
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
        word = word | (sboxSubstitution(byte) << (8*i))
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

def genAllRoundKeys():
    words = getFourWords(key)
    allWords.extend(words)

    for roundNum in range(1, totalRounds+1):
        genRoundKey(roundNum)

def fillMat(words, matrix):
    for i in range(matrixDim):
        for j in range(matrixDim):
            matrix[j][i] = getByte(words[i], 3-j)

def substituteMat():
    for i in range(matrixDim):
        for j in range(matrixDim):
            stateMat[i][j] = sboxSubstitution(stateMat[i][j])

def shiftMatRowCircular(row):
    for _ in range(row):
        temp = stateMat[row][0]
        for i in range(matrixDim-1):
            stateMat[row][i] = stateMat[row][i+1]
        stateMat[row][matrixDim-1] = temp

def shiftMat():
    for row in range(1, matrixDim):
        shiftMatRowCircular(row)

def specialMultiply(a, b):
    b = BitVector(hexstring=b)
    return a.gf_multiply_modular(b, AES_modulus, 8).intValue()

def mixColumns():
    global stateMat
    resultMat = [[0 for _ in range(matrixDim)] for _ in range(matrixDim)]

    # iterate through rows of X
    for i in range(matrixDim):
    # iterate through columns of Y
        for j in range(matrixDim):
            # iterate through rows of Y
            for k in range(matrixDim):
                # print(Mixer[i][k], hex(stateMat[k][j]))
                resultMat[i][j] ^= specialMultiply(Mixer[i][k], hex(stateMat[k][j])[2:4])

    stateMat = resultMat

def addRoundKey(roundNum):
    fillMat(allWords[roundNum*4:roundNum*4 + 4], keyMat)
    for i in range(matrixDim):
        for j in range(matrixDim):
            stateMat[i][j] = stateMat[i][j] ^ keyMat[i][j]

def runRounds(roundNum):
    if roundNum != 0:
        substituteMat()
        shiftMat()
        if roundNum != totalRounds:
            mixColumns()
    
    addRoundKey(roundNum)

genAllRoundKeys()
fillMat(getFourWords(plainText), stateMat)
for roundNum in range(totalRounds+1):
    runRounds(roundNum)
    
for i in range(matrixDim):
    for j in range(matrixDim):
        print(hex(stateMat[i][j]), end=" ")
    print()