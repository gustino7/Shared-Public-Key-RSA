# Python program to implement client side of chat room.
import socket
import select
import sys
from math import ceil
import time
import random

IP = '192.226.1.2'
Port = 54321
key = str()
username = str()
clientIp = str()
messageSize = 2048
maxNum = 999999999

# list of other client's and its public keys
clients = []

# connection status, true if client is in a chat session
connected = False
currConnected = str()

# --------------- DES Algorithm --------------- #

def DES_Encrypt(msg, key):
    plaintext_block_size = 8
    plaintext_initial_permutation = (2, 6, 3, 1, 4, 8, 5, 7)
    plaintext_expansion_permutation = (4, 1, 2, 3, 2, 3, 4, 1)
    substitution_box_0 =[[1, 0, 3, 2],
                         [3, 2, 1, 0],
                         [0, 2, 1, 3],
                         [3, 1, 3, 2]]
    substitution_box_1 =[[0, 1, 2, 3],
                         [2, 0, 1, 3],
                         [3, 0, 1, 0],
                         [2, 1, 0, 3]]
    right_half_permutation_box = (2, 4, 3, 1)
    inverse_initial_permutation = (4, 1, 3, 5, 7, 2, 8, 6)

    plaintext = msg.rstrip()
    permuted_plaintext = []
    subkeys = generate_subkeys(key)

    for i in plaintext :
        binary_plaintext = format(ord(i), "0{}b".format(plaintext_block_size))
        permuted_plaintext.append(__get_permuted_value(binary_plaintext, plaintext_initial_permutation))

    k = 0
    for key in subkeys :
        i = 0
        for block in permuted_plaintext :
            left_half = block[:4]
            right_half = block[4:]
            new_left_half = right_half

            right_half = __get_permuted_value(right_half, plaintext_expansion_permutation)
            temp = xor_operation(int(right_half, 2), int(key, 2))
            right_half = format(temp, "0{}b".format(len(block)))

            right_half = __perform_substitution(right_half[:4], substitution_box_0) + \
                            __perform_substitution(right_half[4:], substitution_box_1)
            
            right_half = __get_permuted_value(right_half, right_half_permutation_box)

            temp = xor_operation(int(right_half, 2), int(left_half, 2))
            new_right_half = format(temp, "0{}b".format(int(len(block)/2)))

            if (k == len(subkeys) - 1) :
                permuted_plaintext[i] = new_right_half + new_left_half
            else :
                permuted_plaintext[i] = new_left_half + new_right_half
            i += 1
        k += 1
    ciphertext = []
    for block in permuted_plaintext :
        ciphertext.append(__get_permuted_value(block, inverse_initial_permutation))

    result = "".join(ciphertext)
    return result

def DES_Decryption(ciphertext, key):
    plaintext_block_size = 8
    plaintext_initial_permutation = (2, 6, 3, 1, 4, 8, 5, 7)
    plaintext_expansion_permutation = (4, 1, 2, 3, 2, 3, 4, 1)
    substitution_box_0 =[[1, 0, 3, 2],
                         [3, 2, 1, 0],
                         [0, 2, 1, 3],
                         [3, 1, 3, 2]]
    substitution_box_1 =[[0, 1, 2, 3],
                         [2, 0, 1, 3],
                         [3, 0, 1, 0],
                         [2, 1, 0, 3]]
    right_half_permutation_box = (2, 4, 3, 1)
    inverse_initial_permutation = (4, 1, 3, 5, 7, 2, 8, 6)

    subkeys = generate_subkeys(key)
    subkeys.reverse()

    ciphertext_blocks = []
    i = 0
    while (i < len(ciphertext)) :
        temp = ciphertext[i:i+plaintext_block_size]
        ciphertext_blocks.append(__get_permuted_value(temp, plaintext_initial_permutation))
        i = i + 8

    k = 0
    for key in subkeys :
        i = 0
        for block in ciphertext_blocks :
            left_half = block[:4]
            right_half = block[4:]
            new_left_half = right_half

            right_half = __get_permuted_value(right_half, plaintext_expansion_permutation)
            temp = xor_operation(int(right_half, 2), int(key, 2))
            right_half = format(temp, "0{}b".format(len(block)))

            right_half = __perform_substitution(right_half[:4], substitution_box_0) + \
                            __perform_substitution(right_half[4:], substitution_box_1)
            right_half = __get_permuted_value(right_half, right_half_permutation_box)

            temp = xor_operation(int(right_half, 2), int(left_half, 2))
            new_right_half = format(temp, "0{}b".format(int(len(block)/2)))
            if (k == len(subkeys) - 1) :
                ciphertext_blocks[i] = new_right_half + new_left_half
            else :
                ciphertext_blocks[i] = new_left_half + new_right_half
            i += 1
        k += 1

    plaintext = []
    for block in ciphertext_blocks :
        temp = __get_permuted_value(block, inverse_initial_permutation)
        plaintext.append(chr(int(temp, 2)))

    result = "".join(plaintext)
    return result

def generate_subkeys(key):
    key = int(key)
    key_size = 10
    subkey_initial_permutation = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
    subkey_compression_permutation = (6, 3, 7, 4, 8, 5, 10, 9)
    no_of_rounds = 16
    key_shift_values = (2, 1)
    key = format(key, "0{}b".format(key_size))
    permuted_key = __get_permuted_value(key, subkey_initial_permutation)
    all_subkeys = []

    for i in range(no_of_rounds) :
        left_half = permuted_key[:int(key_size/2)]
        right_half = permuted_key[int(key_size/2):]

        left_half = format(circular_left_shift(int(left_half, 2), key_shift_values[i%2], int(key_size/2)), \
                            "0{}b".format(int(key_size/2)))
        right_half = format(circular_left_shift(int(right_half, 2), key_shift_values[i%2], int(key_size/2)), \
                            "0{}b".format(int(key_size/2)))
        
        merged_halfs = left_half + right_half
        all_subkeys.append(__get_permuted_value(merged_halfs, subkey_compression_permutation))
        permuted_key = merged_halfs
    return all_subkeys

def __get_permuted_value(data, permutation) :
        permuted_value = []
        for i in permutation :
            permuted_value.append(data[i - 1])
        return("".join(permuted_value))

def circular_left_shift(num, shift_amount, size_of_shift_register) :
        binary_rep = "{0:0{1}b}".format(num, size_of_shift_register)
        shift_amount = shift_amount % size_of_shift_register
        ans = binary_rep[shift_amount:] + binary_rep[:shift_amount]
        return int(ans, 2)

def xor_operation(a, b) :
        return a ^ b

def __perform_substitution(data, sub_box) :
        row_number = int(data[0] + data[3], 2)
        column_number = int(data[1] + data[2], 2)
        return format(sub_box[row_number][column_number], "02b")

# --------------- RSA Algorithm --------------- #

# variable for rsa
p = 17
q = 19
n = p * q
phi = (p-1) * (q-1)
pubKeyList = list()

# gcd
def gcd(x, y):
    while (y):
        x, y = y, x % y
    return abs(x)


# list all possible public key
for i in range(2, phi):
    if (gcd(i, phi) == 1):
        pubKeyList.append(i)

# set rsa key for the client
e = random.choice(pubKeyList)   # pubkey
d = 0                           # prkey
while ((d * e) % phi != 1):
    d += 1
pubKey = (e, n)
prKey = d

# result for x^y mod p
def modex(x, y, p):
    res = 1

    while(y>0):
        if ((y & 1) != 0):
            res = (res * x)%p
 
        y = y >> 1
        x = x * x 
 
    return res % p

# rsa encryption
def rsa_encrypt(message, pubKey):
    print(f"Encrypt {message}:")
    pt = str(message)
    ct = str()
    ptList = []
    ctList = []
    blockSize = n

    # for each character
    for char in pt:
        ptNum = ord(char)
        ptList = [ptNum] + ptList
        ctNum = modex(ptNum, pubKey, blockSize)
        ctList = [ctNum] + ctList
        ct = chr(ctNum) + ct

    print("Before encryption:")
    print(f"In decimal: {ptList}")
    # print(f"In ascii: {pt}")
    print("After encryption:")
    print(f"In decimal: {ctList}")
    # print(f"In ascii: {ct}")

    return ct

# rsa decryption
def rsa_decrypt(message, prKey):
    print(f"Decrypt{message}:")
    ct = str(message)
    pt = str()
    ptList = []
    ctList = []
    blockSize = n

    # for each character
    for char in ct:
        ctNum = ord(char)
        ctList = [ctNum] + ctList
        ptNum = modex(ctNum, prKey, blockSize)
        ptList = [ptNum] + ptList
        pt = chr(ptNum) + pt
    
    print("Before decryption:")
    print(f"In decimal: {ctList}")
    # print(f"In ascii: {ct}")
    print("After decryption:")
    print(f"In decimal: {ptList}")
    # print(f"In ascii: {pt}")

    return pt

# search pubkeys
def searchPubkeys(addr):
    for client in clients:
        if(client['addr'] == addr):
            return client['pubKey']

if __name__ == "__main__":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.connect((IP, Port))

    # get IP that connect to server
    clientIp = server.recv(messageSize).decode('utf-8')

    # send public key
    server.send(str(pubKey).encode('utf-8'))

    # get all client's public key from server
    clientList = server.recv(2048).decode('utf-8')
    clients = eval(clientList)
    print(f"Daftar client:")

    # client belum ada
    if(len(clients) == 0):
        print("Tidak ada client yang terkoneksi")
    # client ada
    else:
        for i in range(len(clients)):
            print(f"{i+1}. {clients[i]['addr']}")
        print("Membuat koneksi ke? ex: 1\n")

    while True:
        sockets_list = [sys.stdin, server]

        read_sockets, write_socket, error_socket = select.select(sockets_list, [], [])

        for socks in read_sockets:
            # client is not in chat session
            if not connected:
                if socks == server:
                    data = socks.recv(messageSize)
                    data = data.decode('utf-8')
                    data = eval(data)

                    # new client's public key
                    if (data['type'] == "pubkey"):
                        clients.append(data['message'])
                        print(f"Client {data['message']['addr']} telah terhubung")
                        print(f"Daftar client:")
                        # client belum ada
                        if(len(clients) == 0):
                            print("Belum ada client yang terkoneksi")
                        # client ada
                        else:
                            for i in range(len(clients)):
                                print(f"{i+1}. {clients[i]['addr']}")
                            print("Mau membuat koneksi ke siapa?\n")

                    # there is other client want to connect
                    elif (data['type'] == "new connection"):
                        print(data['src'] + " mau buat koneksi nih... terima? (ya/tidak)")
                        answer = input()

                        # invalid input
                        while(answer != "ya" and answer != "tidak"):
                            print("Invalid input, masukkan \"ya\" atau \"tidak\"")
                            answer = input()

                        # accept
                        if(answer == "ya"):
                            reply={
                                "type": "reply connection",
                                "dest": data['src'],
                                "src": clientIp,
                                "message": "accept"
                            }
                            server.send(str(reply).encode('utf-8'))
                            
                            tempPubKey = searchPubkeys(data['src'])
                            tempPubKey = tempPubKey[0]

                            # menerima N1 dan IdA
                            msg = server.recv(messageSize).decode('utf-8')
                            msg = eval(msg)
                            N1, IdA = msg['message'].split(',')
                            N1 = rsa_decrypt(N1, prKey)
                            print(f"N1 yang diterima: {N1}\n")
                            IdA = rsa_decrypt(IdA, prKey)
                            print(f"Id yang diterima: {IdA}\n")

                            # kirim N1 dan N2
                            N2 = random.randint(0, maxNum)
                            N2 = str(N2)
                            print(f"Mengirim  N1: {N1}")
                            N1 = rsa_encrypt(N1, tempPubKey)
                            print('-'*40)

                            print(f"Mengirim  N2: {N2}")
                            N2 = rsa_encrypt(N2, tempPubKey)
                            print('-'*40)

                            msg = f"{N1},{N2}"
                            n1n2 = {
                                'dest': data['src'],
                                'src': clientIp,
                                'message': msg
                            }
                            server.send(str(n1n2).encode('utf-8'))

                            # menerima N2
                            N2 = server.recv(messageSize).decode('utf-8')
                            N2 = eval(N2)
                            N2 = N2['message']
                            N2 = rsa_decrypt(N2, prKey)
                            print(f"N2 yang diterima: {N2}")
                            print('-'*40)

                            # kirim session key
                            # Session Key bisa diubah
                            key = 532
                            print(f"Mengirim  key: {key}")
                            encKey = rsa_encrypt(key, tempPubKey)
                            print('-'*40)
                            keyData = {
                                'dest': data['src'],
                                'src': clientIp,
                                'message': encKey
                            }
                            server.send(str(keyData).encode('utf-8'))

                            # Koneksi berhasil
                            connected = True
                            currConnected = data['src']
                            connectionMessage = {
                                'dest': None,
                                'addr': currConnected
                            }
                            server.send(str(connectionMessage).encode('utf-8'))
                            print(f"Berhasil membuat koneksi dengan {currConnected}")
                            print(f"Sesi chat telah dimulai dengan session key = {key} (ketik 'exit untuk keluar sesi')\n")
                        # reject
                        else:
                            data={
                                "type": "reply connection",
                                "dest": data['src'],
                                "src": clientIp,
                                "message": "reject"
                            }
                            server.send(str(data).encode('utf-8'))

                    # another client send reply connection
                    elif (data['type'] == "reply connection"):
                        # client accept
                        if(data["message"] == "accept"):
                            # mencari public key client
                            tempPubKey = searchPubkeys(data['src'])
                            tempPubKey = tempPubKey[0]

                            # kirim N1 dan Id A
                            N1 = random.randint(0, maxNum)
                            N1 = str(N1)

                            print(f"Mengirim  N1: {N1}")
                            N1 = rsa_encrypt(N1, tempPubKey)
                            print('-'*40)

                            print(f"Mengirim  Id: {clientIp}")
                            IdA = rsa_encrypt(clientIp, tempPubKey)
                            print('-'*40)

                            msg = f"{N1},{IdA}"
                            n1Id = {
                                'dest': data['src'],
                                'src': clientIp,
                                'message': msg
                            }
                            server.send(str(n1Id).encode('utf-8'))

                            # menerima N1, N2
                            msg = server.recv(messageSize).decode('utf-8')
                            msg = eval(msg)
                            N1, N2 = msg['message'].split(',')
                            N1 = rsa_decrypt(N1, prKey)
                            print(f"N1 yang diterima: {N1}")
                            print('-'*40)

                            N2 = rsa_decrypt(N2, prKey)
                            print(f"N2 yang diterima: {N2}")
                            print('-'*40)

                            # kirim N2
                            print(f"Mengirim  N2: {N2}")
                            N2 = rsa_encrypt(N2, tempPubKey)
                            print('-'*40)

                            n2 = {
                                'dest': data['src'],
                                'src': clientIp,
                                'message': N2
                            }
                            server.send(str(n2).encode('utf-8'))

                            # menerima N1 dan session Key
                            key = server.recv(messageSize).decode('utf-8')
                            key = eval(key)
                            key = key['message']
                            # key = [key[i:i+8] for i in range(0, len(key), 8)]
                            key = rsa_decrypt(key, prKey)
                            print(f"Key yang diterima: {key}")
                            print('-'*40)

                            # koneksi berhasil
                            connected = True
                            currConnected = data['src']
                            connectionMessage = {
                                'dest': None,
                                'addr': currConnected
                            }
                            server.send(str(connectionMessage).encode('utf-8'))
                            print(f"Berhasil membuat koneksi dengan {currConnected}")
                            print(f"Sesi chat telah dimulai dengan session key = {key} (ketik 'exit untuk keluar sesi')\n")
                        # client reject
                        elif(data["message"] == "reject"):
                            print(f"{data['src']} menolak koneksi")

                # try to connect to other client
                else:
                    selectedClient =int(input())

                    # invalid input
                    while(selectedClient<1 or selectedClient>len(clients)):
                        print("Invalid Input")
                        print("Mau membuat koneksi ke siapa?")
                        selectedClient = input("> ")

                    data = {
                        'type': 'new connection',
                        "src": clientIp,
                        'dest': clients[selectedClient-1]['addr']
                    }
                    server.send(str(data).encode('utf-8'))

                    print('Sedang menunggu jawaban ...')

            # client is in chat session
            else:
                if socks == server:
                    message = socks.recv(2048)
                    message = message.decode('utf-8')
                    addr, ciphertext, length = message.split(',')
                    length = int(length)

                    plaintext = DES_Decryption(ciphertext, key)
                    print(f"Sender: {addr}")
                    print(f"Cipher Text: { ciphertext }")
                    print(f"message: { plaintext }\n")
                    sys.stdout.flush()
                else:
                    plaintext = input()
                    # if user exit chat session
                    if(plaintext == 'exit'):
                        pass
                    ciphertext = DES_Encrypt(plaintext, key)

                    message = f"{ciphertext},{len(plaintext)}"
                    server.send(message.encode('utf-8'))
                    print(f"Sender: You")
                    print(f"message: { plaintext }")
                    print(f"Cipher Text: { ciphertext }\n")
                    sys.stdout.flush()

    server.close()
