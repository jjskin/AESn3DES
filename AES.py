from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from secrets import token_bytes
import datetime

key = token_bytes(24)

def TDESEncrypt(read):
    reszta = 24 - len(read)%24
    read = read + b' '*reszta

    cipherT = DES3.new(key, DES3.MODE_ECB)

    pDES3 = cipherT.encrypt(read)

    return pDES3

def TDESDecrypt(read):
    cipherT = DES3.new(key, DES3.MODE_ECB)
    
    pDES3 = cipherT.decrypt(read)

    return pDES3

def AESEncrypt(read):
    reszta = 32 - len(read)%32
    read = read + b' '*reszta

    cipher = AES.new(key, AES.MODE_ECB)

    pAES = cipher.encrypt(read)

    return pAES

def AESDecrypt(read):
    cipher = AES.new(key, AES.MODE_ECB)

    pAES = cipher.decrypt(read)

    return pAES 

#Input file--------------------------------------------------------------------------------------#
input = open("input.txt", "rb")
read = input.read()
#------------------------------------------------------------------------------------------------#


#AES kodowanie-----------------------------------------------------------------------------------#
startAESE = datetime.datetime.now()
outBytesAES = AESEncrypt(read)
durationAESE = datetime.datetime.now() - startAESE

outByte = open('outputBytesAES.bin', 'wb')
outByte.write(outBytesAES)
outByte.close()
#------------------------------------------------------------------------------------------------#


#3DES kodowanie----------------------------------------------------------------------------------#
startTDesE = datetime.datetime.now()
outBytes3DES = TDESEncrypt(read)
durationTDesE = datetime.datetime.now() - startTDesE

outByte2 = open('outputByte3DES.bin', 'wb')
outByte2.write(outBytes3DES)
outByte2.close()
#------------------------------------------------------------------------------------------------#


#AES dekodowanie---------------------------------------------------------------------------------#
inputByte = open('outputBytesAES.bin', 'rb')
readAES = inputByte.read()
inputByte.close()

startAESD = datetime.datetime.now()
outAES = AESDecrypt(readAES)
durationAESD = datetime.datetime.now() - startAESD

output = open('outputAES.txt', 'w')
output.write(bytes.fromhex(outAES.hex()).decode('utf-8'))
output.close()
#------------------------------------------------------------------------------------------------#


#3DES dekodowanie--------------------------------------------------------------------------------#
inputByte2 = open('outputByte3DES.bin', 'rb')
read3DES = inputByte2.read()
inputByte2.close()

startTDesD = datetime.datetime.now()
out3DES = TDESDecrypt(read3DES)
durationTDesD = datetime.datetime.now() - startTDesD

output2 = open('output3DES.txt', 'w')
output2.write(bytes.fromhex(out3DES.hex()).decode('utf-8'))
output2.close()
#------------------------------------------------------------------------------------------------#


#Klucze------------------------------------------------------------------------------------------#
print("Klucz hex AES:               ", key.hex()) 
print("Klucz hex 3DES:              ", key.hex())
#------------------------------------------------------------------------------------------------#


#Czasy-------------------------------------------------------------------------------------------#
print("Czas kodowania AES:          ", durationAESE)
print("Czas kodowania 3DES:         ", durationTDesE)
print("Czas dekodowania AES:        ", durationAESD)
print("Czas dekodowania 3DES:       ", durationTDesD)
#------------------------------------------------------------------------------------------------#

input.close()