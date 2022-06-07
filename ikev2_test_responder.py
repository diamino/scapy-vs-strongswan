from scapy.all import *
from scapy.contrib.ikev2 import *
from scapy.utils import inet_aton
import binascii
import os
import ikev2_lib
import socket

# IKEv2 specification: https://tools.ietf.org/pdf/rfc7296.pdf

INITIATOR_IP = '172.17.0.3'
INITIATOR_PORT = 500
RESPONDER_IP = '172.17.0.2'
RESPONDER_PORT = 500

# Create dummy UDP listener to prevent ICMP port unreachable messages
sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.bind((RESPONDER_IP, RESPONDER_PORT))

nonce_r = os.urandom(32)
spi_r = b'Ysblokje'

dh = ikev2_lib.DiffieHellman()

capture = sniff(filter=f"dst host {RESPONDER_IP} and dst port {RESPONDER_PORT}", count=1)
capture.summary()

packet = capture[0][IP]

packet.show()

dh_a = dh.generate_public().to_bytes(length=256, byteorder='big') 
dh_b = int.from_bytes(packet[IKEv2_payload_KE].load, byteorder='big')

dhs = dh.generate_shared(dh_b).to_bytes(length=256, byteorder='big')
print(f"shared Diffie Hellman secret: {binascii.b2a_hex(dhs).decode()}")

nonce_i = packet[IKEv2_payload_Nonce].load
spi_i = packet[IKEv2].init_SPI

print(f"SPIi: {spi_i}")
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

# Build IKE_SA_INIT reponse

# Get proposal from Initiator IKE_SA_INIT 
proposal = packet[IKEv2_payload_Proposal]

hdr = IKEv2(init_SPI = spi_i, resp_SPI=spi_r, next_payload = 'SA', exch_type = 'IKE_SA_INIT', flags='Response')
sa = IKEv2_payload_SA(next_payload = 'KE', prop=proposal)
ke = IKEv2_payload_KE(next_payload = 'Nonce', group = '2048MODPgr', load = dh_a)
nonce = IKEv2_payload_Nonce(next_payload = 'None', load = nonce_r)

ike_sa_init = hdr/sa/ke/nonce
#ike_sa_init = IKEv2()/IKEv2_payload_SA(prop=proposal)/IKEv2_payload_KE()/IKEv2_payload_Nonce()

packet = IP(dst = INITIATOR_IP)/UDP(dport = INITIATOR_PORT, sport = RESPONDER_PORT)/ike_sa_init

#packet.show()

# Send IKE_SA_INIT response and receive IKE_AUTH
ans = sr1(packet)

#ans.show()


interact(mydict=globals(), mybanner="IKEv2 test Responder v0.1")
