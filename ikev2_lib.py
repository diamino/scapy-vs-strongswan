import os
import hmac, hashlib
from typing import Callable
from Cryptodome.Cipher import AES

# Diffie Hellman groups (RFC3526)[https://tools.ietf.org/html/rfc3526]
dhgroups = {
    # 2048-bit
    14: {
    "prime": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF,
    "generator": 2
    }
}

# Integrity algorithms [IANA IKEv2 parameters](https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-7)
integrity = {
    2: {
        "name": "AUTH_HMAC_SHA1_96",
        "hash_algo": hashlib.sha1,
        "key_size": 20,
        "hash_size": 12
    },
    12: {
        "name": "AUTH_HMAC_SHA2_256_128",
        "hash_algo": hashlib.sha256,
        "key_size": 32,
        "hash_size": 16
    }
}

# Encryption algorithms [IANA IKEv2 parameters](https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-5)
encryption = {
    12: {
        "name": "ENCR_AES_CBC",
        "key_size": 32,
        "block_size": 16
    }
}

prf = {
    2: {
        "name": "PRF_HMAC_SHA1",
        "hash_algo": hashlib.sha1,
        "key_size": 20,
        "hash_size": 20
    },
    5: {
        "name": "PRF_HMAC_SHA2_256",
        "hash_algo": hashlib.sha256,
        "key_size": 32,
        "hash_size": 32
    }

}

class DiffieHellman:

    def __init__(self, prime=dhgroups[14]['prime'], generator=dhgroups[14]['generator'], secret=None):
        self.prime = prime
        self.generator = generator
        if not secret:
            self.secret = int.from_bytes(os.urandom(32), byteorder='big')
        else:
            self.secret = secret

    def generate_public(self):
        return pow(self.generator, self.secret, self.prime)

    def check_public(self, public):
        # check if the public key is valid based on NIST SP800-56
        # 2 <= g^b <= p-2 and Lagrange for safe primes (g^bq)=1, q=(p-1)/2
        return (2 <= public) and (public <= (self.prime - 2)) and (pow(public, (self.prime - 1) // 2, self.prime) == 1)

    def generate_shared(self, b, unsafe=False):
        if unsafe or self.check_public(b):
            return pow(b, self.secret, self.prime)
        else:
            raise Exception('Unsafe public key!')

def get_prf(prf_algo_id: int) -> Callable[[bytes, bytes], bytes] | None:
    if prf_algo_id not in prf:
        return None

    prf_algo = prf[prf_algo_id]
    def prf_func(key: bytes, msg: bytes) -> bytes:
        return hmac.new(key, msg, prf_algo["hash_algo"]).digest()
    return prf_func 

def PrfHmacSha256(key: bytes, msg: bytes) -> bytes:
    '''
    This function is kept for backwards compatibility. It is encouraged to use
      the `get_prf` function in this module.
    '''
    return hmac.new(key, msg, hashlib.sha256).digest()

def PrfPlus(prf: Callable[[bytes, bytes], bytes], key: bytes, msg: bytes, num_bytes: int, start: int=1) -> bytes:
    # Generate num_bytes of output using the provided prf according to the 
    #  prf+ mode as described in RFC7296, section 2.13
    output = b''
    counter = start
    t = b''
    while len(output) < num_bytes: 
        t = prf(key, t + msg + counter.to_bytes(1, 'big'))
        output += t
        counter += 1
    return output[:num_bytes] 

def calculate_integrity(key: bytes, msg: bytes, integrity_algo_id: int=2) -> bytes:
    integrity_algo = integrity[integrity_algo_id]
    return hmac.new(key, msg, integrity_algo["hash_algo"]).digest()[:integrity_algo["hash_size"]]

def verify_integrity(key: bytes, msg: bytes, checksum: bytes, integrity_algo_id: int=2) -> bool:
    return checksum == calculate_integrity(key, msg, integrity_algo_id=integrity_algo_id)

def generate_iv(encryption_algo_id: int=12) -> bytes:
    return os.urandom(encryption[encryption_algo_id]['block_size'])

def decrypt_message(key: bytes, msg: bytes, iv: bytes, encryption_algo_id: int=12) -> bytes:
    '''
    NB. This function currently only supports AES in CBC mode
    '''
    plain_padded = AES.new(key, AES.MODE_CBC, iv).decrypt(msg)
    pad_length = plain_padded[-1]
    return plain_padded[:-pad_length-1]

def encrypt_message(key: bytes, msg: bytes, iv: bytes, encryption_algo_id: int=12) -> bytes:
    '''
    NB. This function currently only supports AES in CBC mode
    '''
    cipher_block_size = encryption[encryption_algo_id]['block_size']
    # Pad message
    pad_length = cipher_block_size - ((len(msg) + 1) % cipher_block_size)
    padding = bytes(pad_length)
    pad_length_b = pad_length.to_bytes(1, byteorder='big')
    msg_padded = msg + padding + pad_length_b
    # Encrypt message and return
    return AES.new(key, AES.MODE_CBC, iv).encrypt(msg_padded)
