from scapy.all import *
from scapy.contrib.ikev2 import *
from scapy.utils import inet_aton
import binascii
import os
import ikev2_lib

# IKEv2 specification: https://tools.ietf.org/pdf/rfc7296.pdf

IP_INITIATOR = '172.17.0.3'
IP_RESPONDER = '172.17.0.2'

nonce_i = os.urandom(32)
spi_i = b'ColaFles'

dh = ikev2_lib.DiffieHellman()

ke_load = dh.generate_public().to_bytes(length=256, byteorder='big')
#ke_load = binascii.a2b_hex('5c194e0a09a34888806a038640e285046eba3bc9b4ae3d31a5a6811e07aa973c9ed795dcb68380071f05091bf7b3dbf7e76919d903e6f044d4720852f3c8486142fd92947bb5619dd200d287b7a74503ff7de6cba80e893c330e386e81b579ea8252bf7015021fe047283387cd2f0ed61e0e1fc3e011ca845eab3cd859d80a98937f24f23502464a64fa77f8c1bf12f59716eeb4bc34a317fc8a46160f40b2b3e2b52eac5a398c9062344c5ed4fe798b4c9f0b964ad6deb4f05fc63f7292d6f0a742d5bf3353a7be14bcc0c144e2c511342384191718b2d0cecc692bca30235b1b5661151fd4ce43e55dacee2df5969d6421f08c9712bb731c503321102d735d')

'''
Initiator                         Responder
-------------------------------------------------------------------
HDR, SAi1, KEi, Ni  -->                                                 IKE_SA_INIT
                                  <--  HDR, SAr1, KEr, Nr, [CERTREQ]

HDR, SK {IDi, [CERT,] [CERTREQ,]                                        IKE_AUTH
    [IDr,] AUTH, SAi2,
    TSi, TSr}  -->
                                  <--  HDR, SK {IDr, [CERT,] AUTH,
                                         SAr2, TSi, TSr}
'''

# IKEv2 parameters
# https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml

# Encryption transform ID 12 = ENCR_AES_CBC
transform_1 = IKEv2_payload_Transform(next_payload = 'Transform', transform_type = 'Encryption', transform_id = 12, length = 12, key_length = 0x0100)
# PRF transform ID 5 = PRF_HMAC_SHA2_256
transform_2 = IKEv2_payload_Transform(next_payload = 'Transform', transform_type = 'PRF', transform_id = 5)
# Integrity transform ID 2 = AUTH_HMAC_SHA1_96
transform_3 = IKEv2_payload_Transform(next_payload = 'Transform', transform_type = 'Integrity', transform_id = 2)
# Diffie-Hellman Group transform ID 14 = 2048-bit MODP Group
transform_4 = IKEv2_payload_Transform(next_payload = 'last', transform_type = 'GroupDesc', transform_id = 14)

proposal = IKEv2_payload_Proposal(trans_nb = 4, trans = transform_1/transform_2/transform_3/transform_4)

hdr = IKEv2(init_SPI = spi_i, next_payload = 'SA', exch_type = 'IKE_SA_INIT', flags='Initiator')
sa = IKEv2_payload_SA(next_payload = 'KE', prop=proposal)
ke = IKEv2_payload_KE(next_payload = 'Nonce', group = '2048MODPgr', load = ke_load)
nonce = IKEv2_payload_Nonce(next_payload = 'None', load = nonce_i)

ike_sa_init = hdr/sa/ke/nonce
#ike_sa_init = IKEv2()/IKEv2_payload_SA(prop=proposal)/IKEv2_payload_KE()/IKEv2_payload_Nonce()

packet = IP(dst = IP_RESPONDER)/UDP(dport = 500, sport = 500)/ike_sa_init

# Send IKE_SA_INIT and receive response
ans = sr1(packet)

ans.show()

dh_b = int.from_bytes(ans[IKEv2_payload_KE].load, byteorder='big')
dhs = dh.generate_shared(dh_b).to_bytes(length=256, byteorder='big')
print(f"shared Diffie Hellman secret: {binascii.b2a_hex(dhs).decode()}")

nonce_r = ans[IKEv2_payload_Nonce].load
spi_r = ans[IKEv2].resp_SPI
print(f"SPIr: {spi_r}")

print(f"Ni: {binascii.b2a_hex(nonce_i).decode()}")
print(f"Nr: {binascii.b2a_hex(nonce_r).decode()}")

skeyseed = ikev2_lib.PrfHmacSha256(nonce_i + nonce_r, dhs)

print(f"SKEYSEED: {binascii.b2a_hex(skeyseed).decode()}")

# Keys needed: SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr
# Sk_d is 32 bytes (256 bits) based on PRF_HMAC_SHA2_256
# Sk_ai is 20 bytes (160 bits) based on AUTH_HMAC_SHA1_96
# Sk_ar is 20 bytes (160 bits) based on AUTH_HMAC_SHA1_96
# Sk_ei is 32 bytes (256 bits) based on ENCR_AES_CBC
# Sk_er is 32 bytes (256 bits) based on ENCR_AES_CBC
# Sk_pi is 32 bytes (256 bits) based on PRF_HMAC_SHA2_256
# Sk_pr is 32 bytes (256 bits) based on PRF_HMAC_SHA2_256
# Total is 200 bytes

prfplusoutput = ikev2_lib.PrfPlus(ikev2_lib.PrfHmacSha256, skeyseed, nonce_i + nonce_r + spi_i + spi_r, 200)
print(f"prf+ output: {binascii.b2a_hex(prfplusoutput).decode()}")
sk_d = prfplusoutput[:32]
sk_ai = prfplusoutput[32:52]
sk_ar = prfplusoutput[52:72]
sk_ei = prfplusoutput[72:104]
sk_er = prfplusoutput[104:136]
sk_pi = prfplusoutput[136:168]
sk_pr = prfplusoutput[168:200]
print(f"Sk_d: {binascii.b2a_hex(sk_d).decode()}")
print(f"Sk_ai: {binascii.b2a_hex(sk_ai).decode()}")
print(f"Sk_ar: {binascii.b2a_hex(sk_ar).decode()}")
print(f"Sk_ei: {binascii.b2a_hex(sk_ei).decode()}")
print(f"Sk_er: {binascii.b2a_hex(sk_er).decode()}")
print(f"Sk_pi: {binascii.b2a_hex(sk_pi).decode()}")
print(f"Sk_pr: {binascii.b2a_hex(sk_pr).decode()}")

idi_prime = inet_aton(IP_INITIATOR)

# Prepare IKE_AUTH
hdr = IKEv2(init_SPI = spi_i, resp_SPI = spi_r, next_payload = 'Encrypted', exch_type = 'IKE_AUTH', flags='Initiator')
sk = IKEv2_payload_Encrypted(next_payload = 'IDi') # TODO
idi = IKEv2_payload_IDi(next_payload = 'AUTH', IDtype = "IPv4_addr", load=idi_prime)
auth = IKEv2_payload_AUTH(next_payload = 'SA', auth_type = "Shared Key Message Integrity Code", load="xxxxxxx")
# AUTH payload = MAC(ike_sa_init | none_r | prf(Sk_pi, idi_prime'))


# Encryption transform ID 12 = ENCR_AES_CBC
transforms2 = IKEv2_payload_Transform(next_payload = 'last', transform_type = 'Encryption', transform_id = 12, length = 12, key_length = 0x0100)
proposal2 = IKEv2_payload_Proposal(proto = "ESP", SPIsize = 4, SPI = b'Cola', trans_nb = 1, trans = transforms2)
sa2 = IKEv2_payload_SA(next_payload = 'TSi', prop=proposal2)

ts1 = IPv4TrafficSelector(starting_address_v4 = IP_INITIATOR, ending_address_v4 = IP_INITIATOR)
tsi = IKEv2_payload_TSi(next_payload = 'TSr', number_of_TSs = 1, traffic_selector = [ts1])
ts2 = IPv4TrafficSelector(starting_address_v4 = "10.1.0.0", ending_address_v4 = "10.1.255.255")
tsr = IKEv2_payload_TSr(next_payload = 'None', number_of_TSs = 1, traffic_selector = [ts2])

interact(mydict=globals(), mybanner="IKEv2 test v0.1")
