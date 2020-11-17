import aes
from Crypto.Util.Padding import pad, unpad


def checking_aes_realisation():
    with open("Task_2_5.txt", "w") as task2_5:
        data2_5 = b'Here we check CBC mode for AES encryption!'
        key = aes.get_random_bytes(aes.block_size)
        iv = aes.get_random_bytes(aes.block_size)
        enc = aes.encrypt(key, data2_5, 'CBC', iv)
        dec = aes.decrypt(key, enc, 'CBC')
        task2_5.write("Task 2.5\nCheck my CBC AES compare to original AES CBC:\n")
        task2_5.write("----------------------------------------------------\n")
        task2_5.write("Our message: " + data2_5.decode() + "\n")
        task2_5.write("Key: " + key.hex() + "\n")
        task2_5.write("Initial vector: " + iv.hex() + "\n")
        task2_5.write("----------------------------------------------------" + "\n")
        task2_5.write("My CBC encryption result without initial vector: " + enc[aes.block_size:].hex() + "\n")
        task2_5.write("Encrypted text number blocks = " + str(len(enc) / 16 - 1) + "\n")
        task2_5.write("My CBC decryption result: " + dec.decode() + "\n")
        task2_5.write("----------------------------------------------------\n" + "\n")
        cipher = aes.AES.new(key, aes.AES.MODE_CBC, iv)
        enc = cipher.encrypt(pad(data2_5, aes.block_size))
        cipher = aes.AES.new(key, aes.AES.MODE_CBC, iv)
        dec = unpad(cipher.decrypt(enc), aes.AES.block_size)
        task2_5.write("----------------------------------------------------" + "\n")
        task2_5.write("Original CBC encryption result: " + enc.hex() + "\n")
        task2_5.write("Encrypted text number blocks = " + str(len(enc) / 16) + "\n")
        task2_5.write("Original CBC decryption result: " + dec.decode() + "\n")
        task2_5.write("----------------------------------------------------\n")

    with open("Task_3.txt", "w") as task3:
        task3.write("Task 3\n")
        task3.write("----------------------------------------------------\n")
        key = bytes.fromhex('140b41b22a29beb4061bda66b6747e14')
        task3.write("CBC key:" + key.hex() + "\n\n")
        dataCBC1 = '4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81'
        task3.write("CBC Ciphertext 1: " + dataCBC1 + "\n")
        dec = aes.decrypt(key, bytes.fromhex(dataCBC1), 'CBC')
        task3.write("CBC text 1 decryption result: " + dec.decode() + "\n\n")
        dataCBC2 = '5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253'
        task3.write("CBC Ciphertext 2: " + dataCBC2 + "\n")
        dec = aes.decrypt(key, bytes.fromhex(dataCBC2), 'CBC')
        task3.write("CBC text 2 decryption result: " + dec.decode() +"\n")
        task3.write("----------------------------------------------------\n\n")
        key = bytes.fromhex('36f18357be4dbd77f050515c73fcf9f2')
        task3.write("CTR key:" + key.hex() + "\n\n")
        dataCTR1 = '69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329'
        task3.write("CTR Ciphertext 1: " + dataCTR1 + "\n")
        dec = aes.decrypt(key, bytes.fromhex(dataCTR1), 'CTR')
        task3.write("CTR text 1 decryption result: " + dec.decode() + "\n\n")
        dataCTR2 = '770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451'
        task3.write("CBC Ciphertext 2: " + dataCTR2 + "\n")
        dec = aes.decrypt(key, bytes.fromhex(dataCTR2), 'CTR')
        task3.write("CTR text 2 decryption result: " + dec.decode() + "\n")
        task3.write("----------------------------------------------------")

    with open("Task_4.txt", "w") as task4:
        task4.write("\nTask 4\n----------------------------------------------------\n")
        msg = b'Here we use ECB mode for AES encryption!'
        key = aes.get_random_bytes(aes.block_size)
        enc = aes.encrypt(key, msg, 'ECB')
        dec = aes.decrypt(key, enc, 'ECB')
        task4.write("Checking ECB encryption:\n----------------------------------------------------\n")
        task4.write("Our message: " + msg.decode() + "\n")
        task4.write("Key: " + key.hex() + "\n")
        task4.write("ECB encryption result: " + enc.hex() + "\n")
        task4.write("Encrypted text number blocks = " + str(len(enc) / 16) + "\n")
        task4.write("ECB decryption result: " + dec.decode() + "\n")
        task4.write("----------------------------------------------------\n\n")

        msg = b'Here we use CBC mode for AES encryption!'
        key = aes.get_random_bytes(aes.block_size)
        iv = aes.get_random_bytes(aes.block_size)
        enc = aes.encrypt(key, msg, 'CBC', iv)
        dec = aes.decrypt(key, enc, 'CBC')
        task4.write("Checking CBC encryption:\n----------------------------------------------------\n")
        task4.write("Our message: " + msg.decode() + "\n")
        task4.write("Key: " + key.hex() +"\n")
        task4.write("CBC encryption result with initial vector: " + enc.hex() + "\n")
        task4.write("Encrypted text number blocks = " + str(len(enc) / 16 - 1) + "\n")
        task4.write("CBC decryption result: " + dec.decode() + "\n")
        task4.write("----------------------------------------------------\n\n")

        msg = b'Here we use CFB mode for AES encryption!'
        key = aes.get_random_bytes(aes.block_size)
        iv = aes.get_random_bytes(aes.block_size)
        enc = aes.encrypt(key, msg, 'CFB', iv)
        dec = aes.decrypt(key, enc, 'CFB')
        task4.write("Checking CFB encryption:\n----------------------------------------------------\n")
        task4.write("Our message: " + msg.decode() + "\n")
        task4.write("Key: " + key.hex() + "\n")
        task4.write("CFB encryption result with initial vector: " + enc.hex() + "\n")
        task4.write("Encrypted text number blocks = " + str(len(enc) / 16 - 1) + "\n")
        task4.write("CFB decryption result: " + dec.decode() + "\n")
        task4.write("----------------------------------------------------\n\n")

        msg = b'Here we use OFB mode for AES encryption!'
        key = aes.get_random_bytes(aes.block_size)
        iv = aes.get_random_bytes(aes.block_size)
        enc = aes.encrypt(key, msg, 'OFB', iv)
        dec = aes.decrypt(key, enc, 'OFB')
        task4.write("Checking OFB encryption:\n----------------------------------------------------\n")
        task4.write("Our message: " + msg.decode() + "\n")
        task4.write("Key: " + key.hex() + "\n")
        task4.write("OFB encryption result with initial vector: " + enc.hex() + "\n")
        task4.write("Encrypted text number blocks = " + str(len(enc) / 16 - 1) + "\n")
        task4.write("OFB decryption result: " + dec.decode() + "\n")
        task4.write("----------------------------------------------------\n\n")

        msg = b'Here we use CTR mode for AES encryption!'
        key = aes.get_random_bytes(aes.block_size)
        iv = aes.get_random_bytes(aes.block_size)
        enc = aes.encrypt(key, msg, 'CTR', iv)
        dec = aes.decrypt(key, enc, 'CTR')
        task4.write("Checking CTR encryption:\n----------------------------------------------------\n")
        task4.write("Our message: " + msg.decode() + "\n")
        task4.write("Key: " + key.hex() + "\n")
        task4.write("CTR encryption result with initial vector: " + enc.hex() + "\n")
        task4.write("Encrypted text number blocks = " + str(len(enc) / 16 - 1) + "\n")
        task4.write("CTR decryption result: " + dec.decode() + "\n")
        task4.write("----------------------------------------------------")

if __name__ == "__main__":
    checking_aes_realisation()

