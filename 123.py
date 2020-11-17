
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sys


BlockSize = 16
Nonce = bytes.fromhex('c59bcf35')

def Padding(data):
    s = 0
    for i in data:
        s += 1
    pad = (BlockSize - s).to_bytes(1, sys.byteorder)
    # pad = b'\x00'
    for i in range(BlockSize - s):
        data = data + pad
    return data


def bxor(b1, b2):
    parts = []
    for b1, b2 in zip(b1, b2):
        parts.append(bytes([b1 ^ b2]))
    return b''.join(parts)

def AesBlockEncrypt(key, data, isFinalBlock):
    new_data = data
    if isFinalBlock:
        new_data = Padding(data)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(new_data)


def AesEncrypt(key, data, mode, iv=None):
    size = 0
    chipher_data_list = []
    block_list = []
    chipher_data = b''
    for i in data:
        size += 1
    if size % BlockSize == 0:
        block_quantity = size // BlockSize
        flag = False
    else:
        block_quantity = size // BlockSize + 1
        flag = True

    for i in range(block_quantity):
        block_list.append(data[i * BlockSize:(i + 1) * BlockSize])

    if mode == 'ECB':
        for i in range(block_quantity):
            if (i == block_quantity - 1) and (flag):
                finalFlag = True
            else:
                finalFlag = False
            chipher_data_list.append(AesBlockEncrypt(key, block_list[i], finalFlag))
        for obj in chipher_data_list:
            chipher_data = chipher_data + obj
        # for sublist in chipher_data_list:
        #     for item in sublist:
        #         chipher_data.append(item)
    elif mode == 'CBC':
        if iv == None:
            iv = get_random_bytes(BlockSize)

        for i in range(block_quantity):
            if (i == block_quantity - 1) and (flag):
                finalFlag = True
            else:
                finalFlag = False
            if i == 0:
                block_list[i] = bxor(iv, block_list[i])
                chipher_data_list.append(AesBlockEncrypt(key, block_list[i], finalFlag))
            else:
                block_list[i] = bxor(block_list[i-1], block_list[i])
                chipher_data_list.append(AesBlockEncrypt(key, block_list[i], finalFlag))
        for obj in chipher_data_list:
            chipher_data = chipher_data + obj
        chipher_data = iv + chipher_data
    elif mode == 'CFB':
        if iv == None:
            iv = get_random_bytes(BlockSize)
        for i in range(block_quantity):
            if (i == block_quantity - 1) and (flag):
                finalFlag = True
            else:
                finalFlag = False
            if i == 0:
                variable = AesBlockEncrypt(key, iv, finalFlag)
                chipher_data_list.append(bxor(block_list[i], variable))
            else:
                variable = (AesBlockEncrypt(key, chipher_data_list[i - 1], finalFlag))
                chipher_data_list.append(bxor(block_list[i], variable))
        for obj in chipher_data_list:
            chipher_data = chipher_data + obj
        chipher_data = iv + chipher_data
    elif mode == 'OFB':
        if iv == None:
            iv = get_random_bytes(BlockSize)
        ghost_iv = AesBlockEncrypt(key, iv, False)
        for i in range(block_quantity):
            if (i == block_quantity - 1) and (flag):
                finalFlag = True
            else:
                finalFlag = False
            if i == 0:
                chipher_data_list.append(bxor(ghost_iv, block_list[i]))
            else:
                ghost_iv = AesBlockEncrypt(key, ghost_iv, finalFlag)
                chipher_data_list.append(bxor(ghost_iv, block_list[i]))
        for obj in chipher_data_list:
            chipher_data = chipher_data + obj
        chipher_data = iv + chipher_data
    elif mode == 'CTR':
        nonce = bytes.fromhex('c59bcf35')
        if (i == block_quantity - 1) and (flag):
            finalFlag = True
        else:
            finalFlag = False
        for i in range(block_quantity):
            count = i.to_bytes(12, 'big')
            nonce_vector = nonce + count
            chiper_count = AesBlockEncrypt(key, nonce_vector, finalFlag)
            chipher_data_list.append(bxor(block_list[i], chiper_count))
        for obj in chipher_data_list:
            chipher_data = chipher_data + obj
    else:
        print('Wrong mode')



    return chipher_data

def AesBlockDecrypt(key, chipher_data, isFinalBlock):
    new_data = chipher_data
    if isFinalBlock:
        new_data = Padding(chipher_data)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(new_data)

def AesDecrypt(key, chipder_data, mode, iv=None):
    size = 0
    chipher_data_list = []
    block_list = []
    data = b''
    for i in chipder_data:
        size += 1
    if size % BlockSize == 0:
        block_quantity = size // BlockSize
        flag = False
    else:
        block_quantity = size // BlockSize + 1
        flag = True
    for i in range(block_quantity):
        chipher_data_list.append(chipder_data[i * BlockSize:(i + 1) * BlockSize])
    if mode == 'ECB':
        for i in range(block_quantity):
            if (i == block_quantity - 1) and (flag):
                finalFlag = True
            else:
                finalFlag = False
            block_list.append(AesBlockDecrypt(key, chipher_data_list[i], finalFlag))
        for obj in block_list:
            data = data + obj



    return data

















mode = 'ECB'
iv1 = bytes.fromhex('36f18357be4dbd77f050515c73fcf9f2')
iv2 = bytes.fromhex('5b68629feb8606f9a6667670b75b38a5')

key1 = bytes.fromhex('140b41b22a29beb4061bda66b6747e14')
key2 = b'140b41b22a29beb4061bda66b6747e14140b41b22a29beb4061bda66b6747e14'

data1 = bytes('Im Jane. Im nine. Im a pupil of the third form. I go to school every day. I usually get up at 7 o’clock. Then I do exercises, take a shower, wash my face and hands, clean teeth and dress. Then I have breakfast and go t', 'utf-8')
data2 = b'1244235241342353464354363462524'
data4 = bytes.fromhex('12d591')

# key3 = bytes.fromhex('69dda8455c7dd4254bf353b773304eec')
key3 = b'69dda8455c7dd4254bf353b773304eec'
data3 = bytes.fromhex('69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f')

test = AesEncrypt(key3, data1, mode)
print(test)

print(1)

print(AesDecrypt(key3, test, mode).decode())
