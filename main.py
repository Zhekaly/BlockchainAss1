import time
import json
from random import randint
from math import gcd

def hash(text):
    def right_rotate(value, shift):
        return (value >> shift) | (value << (32 - shift)) & 0xFFFFFFFF

    def padding(msg):
        msg_len = len(msg) * 8
        msg += b'\x80'
        while (len(msg) * 8) % 512 != 448:
            msg += b'\x00'
        msg += msg_len.to_bytes(8, 'big')
        return msg

    def process_chunk(chunk, h):
        k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0b5c3, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]

        w = [0] * 64
        for i in range(16):
            w[i] = int.from_bytes(chunk[i * 4:i * 4 + 4], 'big')

        for i in range(16, 64):
            s0 = right_rotate(w[i - 15], 7) ^ right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = right_rotate(w[i - 2], 17) ^ right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

        a, b, c, d, e, f, g, h_ = h

        for i in range(64):
            s1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h_ + s1 + ch + k[i] + w[i]) & 0xFFFFFFFF
            s0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & 0xFFFFFFFF

            h_ = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        return [(a + h[0]) & 0xFFFFFFFF, (b + h[1]) & 0xFFFFFFFF, (c + h[2]) & 0xFFFFFFFF,
                (d + h[3]) & 0xFFFFFFFF, (e + h[4]) & 0xFFFFFFFF, (f + h[5]) & 0xFFFFFFFF,
                (g + h[6]) & 0xFFFFFFFF, (h_ + h[7]) & 0xFFFFFFFF]

    def sha256(msg):
        h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
            0x1f83d9ab, 0x5be0cd19
        ]
        msg = padding(msg.encode('utf-8'))

        for i in range(0, len(msg), 64):
            chunk = msg[i:i + 64]
            h = process_chunk(chunk, h)

        return ''.join(f'{x:08x}' for x in h)

    return sha256(text)


class RSA:
    def __init__(self):
        self.public_key = None
        self.private_key = None

    def generate_keys(self):
        def generate_prime():
            while True:
                num = randint(100, 999)
                if all(num % i != 0 for i in range(2, int(num ** 0.5) + 1)):
                    return num

        p = generate_prime()
        q = generate_prime()
        n = p * q
        phi = (p - 1) * (q - 1)

        e = randint(2, phi - 1)
        while gcd(e, phi) != 1:
            e = randint(2, phi - 1)

        d = pow(e, -1, phi)
        self.public_key = (e, n)
        self.private_key = (d, n)

    def encrypt(self, message, key):
        e, n = key
        return [pow(ord(char), e, n) for char in message]

    def decrypt(self, cipher, key):
        d, n = key
        return ''.join(chr(pow(char, d, n)) for char in cipher)

    def sign(self, private_key, document):
        return self.encrypt(document, private_key)

    def verify(self, public_key, document, signature):
        decrypted_doc = self.decrypt(signature, public_key)
        return decrypted_doc == document


class Transaction:
    def __init__(self, sender, receiver, amount, private_key):
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.signature = None
        self.private_key = private_key

    def sign_transaction(self, rsa):
        document = f"{self.sender}->{self.receiver}:{self.amount}"
        self.signature = rsa.sign(self.private_key, document)

    def verify_transaction(self, rsa, public_key):
        document = f"{self.sender}->{self.receiver}:{self.amount}"
        if not rsa.verify(public_key, document, self.signature):
            raise ValueError("Signature is wrong")
        if f"{self.sender}->{self.receiver}:{self.amount}" != document:
            raise ValueError("Document is wrong")


class Block:
    def __init__(self, previous_hash, timestamp, merkle_root):
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.merkle_root = merkle_root
        self.nonce = 0
        self.hash = None

    def calculate_hash(self):
        return hash(self.previous_hash + str(self.timestamp) + self.merkle_root + str(self.nonce))

    def display_block(self):
        print(f"Block Hash: {self.hash}")
        print(f"Merkle Root: {self.merkle_root}")
        print(f"Previous Hash: {self.previous_hash}")
        print(f"Timestamp: {self.timestamp}")
        print(f"Nonce: {self.nonce}")
        print("---------------")


class MerkleTree:
    def __init__(self, transactions):
        self.transactions = transactions

    def build_tree(self):
        hashes = [hash(transaction) for transaction in self.transactions]
        while len(hashes) > 1:
            if len(hashes) % 2 != 0:
                hashes.append(hashes[-1])
            hashes = [hash(hashes[i] + hashes[i + 1]) for i in range(0, len(hashes), 2)]
        return hashes[0]


class Blockchain:
    def __init__(self):
        self.chain = []
        self.transactions = []
        self.wallet = None
        self.difficulty = 4

    def add_transaction(self, transaction):
        self.transactions.append(transaction)
        # Записываем транзакцию в файл после её добавления
        self.record_transaction(transaction)

    def record_transaction(self, transaction):
        # Строка с данными транзакции
        transaction_data = {
            "sender": transaction.sender,
            "receiver": transaction.receiver,
            "amount": transaction.amount,
            "signature": ''.join([str(x) for x in transaction.signature])  # Преобразуем подпись в строку
        }

        # Открываем файл для добавления новых транзакций
        with open("transaction.txt", "a") as file:
            file.write(json.dumps(transaction_data) + "\n")
    def mine_block(self, rsa):
        timestamp = int(time.time())
        merkle_tree = MerkleTree([f"{t.sender}->{t.receiver}:{t.amount}" for t in self.transactions])
        merkle_root = merkle_tree.build_tree()
        previous_hash = self.chain[-1].hash if self.chain else "0"
        block = Block(previous_hash, timestamp, merkle_root)

        while True:
            block_hash = block.calculate_hash()
            if block_hash[:self.difficulty] == "0000":
                block.hash = block_hash
                break
            block.nonce += 1

        self.chain.append(block)
        return block


rsa = RSA()
rsa.generate_keys()

blockchain = Blockchain()

transaction1 = Transaction("Alice", "Bob", 10, rsa.private_key)
transaction1.sign_transaction(rsa)
blockchain.add_transaction(transaction1)

mined_block1 = blockchain.mine_block(rsa)
mined_block1.display_block()

transaction2 = Transaction("Charlie", "Dave", 20, rsa.private_key)
transaction2.sign_transaction(rsa)
blockchain.add_transaction(transaction2)

mined_block2 = blockchain.mine_block(rsa)
mined_block2.display_block()


