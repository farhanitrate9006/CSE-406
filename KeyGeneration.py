from BitvectorDemo import *

key = "Thats my Kung Fu"
plainText = "Two One Nine Two"
roundConstant = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
allWords = list()
totalRounds = 10
matrixDim = 4

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

def addRoundConstant(word, round):
    word = word ^ (roundConstant[round-1] << 24)
    return word

def changeRightmostWord(word, round):
    word = byteLeftShiftCircular(word)
    word = byteSubstitution(word)
    word = addRoundConstant(word, round)
    return word

def genRoundKey(round):
    roundToUse = round-1
    allWords.append(allWords[roundToUse*4] ^ changeRightmostWord(allWords[round*4 - 1], round))
    for i in range(3):
        allWords.append(allWords[roundToUse*4 + i + 1] ^ allWords[round*4 + i])

def genAllRoundKeys():
    words = getFourWords(key)
    allWords.extend(words)

    for round in range(1, totalRounds+1):
        genRoundKey(round)

def fillStateMat():
    words = getFourWords(plainText)

    for i in range(matrixDim):
        for j in range(matrixDim):
            stateMat[j][i] = getByte(words[i], 3-j)

def fillKeyMat(round):
    words = allWords[round*4 : round*4 + 4]
    #print(words)

    for i in range(matrixDim):
        for j in range(matrixDim):
            keyMat[j][i] = getByte(words[i], 3-j)

def roundZero():
    fillKeyMat(0)
    for i in range(matrixDim):
        for j in range(matrixDim):
            stateMat[i][j] = stateMat[i][j] ^ keyMat[i][j]

genAllRoundKeys()
# for word in allWords:
#     print(hex(word))

fillStateMat()
roundZero()
for i in range(matrixDim):
    for j in range(matrixDim):
        print(hex(stateMat[i][j]), end=" ")
    print()