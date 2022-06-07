import hmac, hashlib
import os

# Diffie Hellman groups (RFC3526)[https://tools.ietf.org/html/rfc3526]
dhgroups = {
    # 2048-bit
    14: {
    "prime": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF,
    "generator": 2
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


def PrfHmacSha256(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()

def PrfPlus(prf, key, msg, num_bytes, start=1):
    # Generate num_bytes of output using the provided prf according to the 
    #  prf+ mode as described in RFC7296, section 2.13
    output = b''
    counter = start
    t = b''
    while len(output) < num_bytes: 
        t = prf(key, t + msg + counter.to_bytes(1, 'big'))
        output += t
        counter += 1
    return output 
