import os
import sys
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

class DeterministicRNG:
    """
    Simula un generador de números aleatorios usando una semilla fija (Strong Key).
    """
    def __init__(self, seed):
        self.seed = seed
        self.counter = 0

    def __call__(self, n):
        result = b""
        while len(result) < n:
            # Estiramos la semilla usando hashing para obtener 'n' bytes
            hash_input = self.seed + self.counter.to_bytes(4, 'big')
            result += SHA256.new(hash_input).digest()
            self.counter += 1
        return result[:n]
