# Strongswan on Docker #

## Run container ##
```
docker run -it --name strongswan -p 500:500/udp -p 4500:4500/udp -v $PWD:/opt --privileged debian:latest
```

## Install packages ##
```
apt update
apt install -y strongswan strongswan-pki libcharon-extra-plugins
```

## Generate keys and certificates and move into place ##
```
mkdir -p /opt/pki/{cacerts,certs,private}
chmod 700 /opt/pki

# generate CA key
ipsec pki --gen --type rsa --size 4096 --outform pem > /opt/pki/private/ca-key.pem
# generate (self signed) CA certificate
ipsec pki --self --ca --lifetime 3650 --in /opt/pki/private/ca-key.pem --type rsa --dn "CN=VPN root CA" --outform pem > /opt/pki/cacerts/ca-cert.pem
# generate server key
ipsec pki --gen --type rsa --size 4096 --outform pem > /opt/pki/private/server-key.pem
# generate server certificate and sign by CA
ipsec pki --pub --in /opt/pki/private/server-key.pem --type rsa | ipsec pki --issue --lifetime 1825 --cacert /opt/pki/cacerts/ca-cert.pem --cakey /opt/pki/private/ca-key.pem --dn "CN=strongswan.diamino.nl" --san "strongswan.diamino.nl" --flag serverAuth --flag ikeIntermediate --outform pem > /opt/pki/certs/server-cert.pem

cp -r /opt/pki/* /etc/ipsec.d/
```

## Configure ##
```
mv /etc/ipsec.conf{,.original}
```

Contents of `/etc/ipsec.conf`:
```
config setup
    charondebug="ike 4, knl 1, cfg 0"
    uniqueids=no

conn ikev2-vpn
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%any
    leftid=@strongswan.diamino.nl
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    right=%any
    rightid=%any
    rightauth=eap-mschapv2
    rightsourceip=10.10.10.0/24
    rightdns=8.8.8.8,8.8.4.4
    rightsendcert=never
    eap_identity=%identity
```

Contents of `/etc/ipsec.secrets`:
```
: RSA "server-key.pem"

testuser : EAP "testpass"
```

## Start ##
```
ipsec start --nofork
```