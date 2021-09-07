from scapy.all import *
from scapy.contrib.ikev2 import *
import binascii
import os
import hmac, hashlib

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

nonce_i = os.urandom(32)

dh = DiffieHellman()

ke_load = dh.generate_public().to_bytes(length=256, byteorder='big')
#ke_load = binascii.a2b_hex('5c194e0a09a34888806a038640e285046eba3bc9b4ae3d31a5a6811e07aa973c9ed795dcb68380071f05091bf7b3dbf7e76919d903e6f044d4720852f3c8486142fd92947bb5619dd200d287b7a74503ff7de6cba80e893c330e386e81b579ea8252bf7015021fe047283387cd2f0ed61e0e1fc3e011ca845eab3cd859d80a98937f24f23502464a64fa77f8c1bf12f59716eeb4bc34a317fc8a46160f40b2b3e2b52eac5a398c9062344c5ed4fe798b4c9f0b964ad6deb4f05fc63f7292d6f0a742d5bf3353a7be14bcc0c144e2c511342384191718b2d0cecc692bca30235b1b5661151fd4ce43e55dacee2df5969d6421f08c9712bb731c503321102d735d')

transform_1 = IKEv2_payload_Transform(next_payload = 'Transform', transform_type = 'Encryption', transform_id = 12, length = 12, key_length = 0x0100)
transform_2 = IKEv2_payload_Transform(next_payload = 'Transform', transform_type = 'PRF', transform_id = 5)
transform_3 = IKEv2_payload_Transform(next_payload = 'Transform', transform_type = 'Integrity', transform_id = 2)
transform_4 = IKEv2_payload_Transform(next_payload = 'last', transform_type = 'GroupDesc', transform_id = 14)

proposal = IKEv2_payload_Proposal(trans_nb = 4, trans = transform_1/transform_2/transform_3/transform_4)

hdr = IKEv2(init_SPI = b'ColaFles', next_payload = 'SA', exch_type = 'IKE_SA_INIT', flags='Initiator')
sa = IKEv2_payload_SA(next_payload = 'KE', prop=proposal)
ke = IKEv2_payload_KE(next_payload = 'Nonce', group = '2048MODPgr', load = ke_load)
nonce = IKEv2_payload_Nonce(next_payload = 'None', load = nonce_i)

ike_sa_init = hdr/sa/ke/nonce
#ike_sa_init = IKEv2()/IKEv2_payload_SA(prop=proposal)/IKEv2_payload_KE()/IKEv2_payload_Nonce()

packet = IP(dst = '172.17.0.3')/UDP(dport = 500, sport = 500)/ike_sa_init

ans = sr1(packet)

ans.show()

dh_b = int.from_bytes(ans[IKEv2_payload_KE].load, byteorder='big')
dhs = dh.generate_shared(dh_b).to_bytes(length=256, byteorder='big')
print(f"shared Diffie Hellman secret: {binascii.b2a_hex(dhs).decode()}")

nonce_r = ans[IKEv2_payload_Nonce].load

print(f"Ni: {binascii.b2a_hex(nonce_i).decode()}")
print(f"Nr: {binascii.b2a_hex(nonce_r).decode()}")

skeyseed = PrfHmacSha256(nonce_i + nonce_r, dhs)

print(f"SKEYSEED: {binascii.b2a_hex(skeyseed).decode()}")

interact(mydict=globals(), mybanner="IKEv2 test v0.1")
