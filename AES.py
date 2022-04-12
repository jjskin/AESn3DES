from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from secrets import token_bytes
import math
import datetime

key = token_bytes(24)

def TDESEncrypt(read):
    pDES3 = b''
    ile = int(math.ceil(len(read)/24))
    reszta = 24-len(read)%24
    read = read+' '*reszta
    read = bytes(read, 'utf-8')

    cipherT = DES3.new(key, DES3.MODE_ECB)

    if(len(read)>24): 
        for i in range(0, ile):
            pDES3 = pDES3+cipherT.encrypt(read[(0+24*i):(24+24*i)])
    else:
        pDES3 = cipherT.encrypt(read)

    return pDES3

def TDESDecrypt(read):
    pDES3 = b''
    ile = int(math.ceil(len(read)/24))

    cipherT = DES3.new(key, DES3.MODE_ECB)
    
    if(len(read)>24): 
        for i in range(0, ile):
            pDES3 = pDES3+cipherT.decrypt(read[(0+24*i):(24+24*i)])
    else:
        pDES3 = cipherT.decrypt(read)

    return pDES3   

def AESEncrypt(read):
    pAES = b''
    ile = int(math.ceil(len(read)/32))
    reszta = 32-len(read)%32
    read = read+' '*reszta
    read = bytes(read, 'utf-8')

    cipher = AES.new(key, AES.MODE_ECB)

    if(len(read)>32): 
        for i in range(0, ile):
            pAES = pAES+cipher.encrypt(read[(0+32*i):(32+32*i)])
    else:
        pAES = cipher.encrypt(read)

    return pAES

def AESDecrypt(read):
    pAES = b''
    ile = int(math.ceil(len(read)/32))

    cipher = AES.new(key, AES.MODE_ECB)
    if(len(read)>32): 
        for i in range(0, ile):
            pAES = pAES+cipher.decrypt(read[(0+32*i):(32+32*i)])
    else:
        pAES = cipher.decrypt(read)

    return pAES 

#Input file--------------------------------------------------------------------------------------#
with open('input.txt', 'r') as input:
    read = input.read()
    input.close() 
#------------------------------------------------------------------------------------------------#


#AES kodowanie-----------------------------------------------------------------------------------#
startAESE = datetime.datetime.now()
outBytesAES = AESEncrypt(read)
durationAESE = datetime.datetime.now() - startAESE

with open('outputBytesAES.txt', 'wb') as outByte:
    outByte.write(outBytesAES)
    outByte.close
#------------------------------------------------------------------------------------------------#


#3DES kodowanie----------------------------------------------------------------------------------#
startTDesE = datetime.datetime.now()
outBytes3DES = TDESEncrypt(read)
durationTDesE = datetime.datetime.now() - startTDesE

with open('outputByte3DES.txt', 'wb') as outByte2:
    outByte2.write(outBytes3DES)
    outByte2.close
#------------------------------------------------------------------------------------------------#


#AES dekodowanie---------------------------------------------------------------------------------#
with open('outputBytesAES.txt', 'rb') as outByte2:
    readAES = outByte2.read()
    outByte2.close()

startAESD = datetime.datetime.now()
outAES = AESDecrypt(readAES)
durationAESD = datetime.datetime.now() - startAESD

with open('outputAES.txt', 'w') as output:
    output.write(bytes.fromhex(outAES.hex()).decode('utf-8'))
    output.close
#------------------------------------------------------------------------------------------------#


#3DES dekodowanie--------------------------------------------------------------------------------#
with open('outputByte3DES.txt', 'rb') as outByte2:
    read3DES = outByte2.read()
    outByte2.close()

startTDesD = datetime.datetime.now()
out3DES = TDESDecrypt(read3DES)
durationTDesD = datetime.datetime.now() - startTDesD

with open('output3DES.txt', 'w') as output2:
    output2.write(bytes.fromhex(out3DES.hex()).decode('utf-8'))
    output2.close
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
