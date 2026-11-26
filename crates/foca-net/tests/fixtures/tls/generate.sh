#!/usr/bin/env bash
# Regenerates the TLS test fixtures (run inside this directory; needs the openssl CLI, used only
# here, never at runtime). Chain: root -> issuing CA -> good.test / expired.test; self.test and
# weak.test (RSA-1024, SHA-1) are self-signed. Only server keys are kept (PKCS#8 DER).
set -e
W=$(mktemp -d)
ec(){ openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $W/$1.pem 2>/dev/null; openssl pkcs8 -topk8 -nocrypt -in $W/$1.pem -outform DER -out $1.key.der; }
ec root; ec int; ec good; ec expired; ec self
cat > $W/ext.cnf <<'EOF'
[req]
distinguished_name=dn
[dn]
[ca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
[good]
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
subjectAltName=DNS:good.test,DNS:*.good.test,IP:127.0.0.1,email:admin@good.test,URI:https://good.test/id
crlDistributionPoints=cdp_sect
authorityInfoAccess=@aia_sect
[cdp_sect]
fullname=@cdp_names
[cdp_names]
URI.1=http://pki.corp.local/crl/issuing.crl
URI.2=ldap:///CN=Corp%20Issuing%20CA,CN=PKI01,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=corp,DC=local?certificateRevocationList?base?objectClass=cRLDistributionPoint
[aia_sect]
OCSP;URI.1=http://ocsp.corp.local/ocsp
caIssuers;URI.2=ldap:///CN=Corp%20Issuing%20CA,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=corp,DC=local?cACertificate?base?objectClass=certificationAuthority
caIssuers;URI.3=http://pki.example.com/issuing.crt
[expired]
basicConstraints=CA:FALSE
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
subjectAltName=DNS:expired.test
[self]
basicConstraints=CA:FALSE
subjectKeyIdentifier=hash
subjectAltName=DNS:self.test
EOF
C=$W/ext.cnf
openssl req -new -x509 -key $W/root.pem -subj "/C=UA/O=FOCA Test PKI/CN=FOCA Test Root CA" -not_before 20250101000000Z -not_after 21250101000000Z -config $C -extensions ca -out $W/root.crt
sign(){
 openssl req -new -key $W/$1.pem -subj "$2" -config $C -out $W/$1.csr
 openssl x509 -req -in $W/$1.csr -CA $W/$3.crt -CAkey $W/$3.pem -set_serial 0x$(openssl rand -hex 8) -extfile $C -extensions $4 -not_before $5 -not_after $6 -sha256 -out $W/$1.crt; }
sign int "/C=UA/O=FOCA Test PKI/CN=FOCA Test Issuing CA" root ca 20250101000000Z 21250101000000Z
sign good "/C=UA/ST=Kyiv/L=Kyiv/O=Good Test LLC/OU=IT Security/CN=good.test/emailAddress=pki@good.test" int good 20250101000000Z 21250101000000Z
sign expired "/O=Expired Corp/CN=expired.test" int expired 20250101000000Z 20250601000000Z
openssl req -new -x509 -key $W/self.pem -subj "/O=Self Corp/CN=self.test" -not_before 20250101000000Z -not_after 21250101000000Z -config $C -extensions self -out $W/self.crt
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out $W/weak.pem 2>/dev/null
openssl req -new -x509 -key $W/weak.pem -sha1 -subj "/O=Weak Corp/OU=Legacy/CN=weak.test" -not_before 20250101000000Z -not_after 21250101000000Z -config $C -extensions self -out $W/weak.crt
for n in root int good expired self weak; do openssl x509 -in $W/$n.crt -outform DER -out $n.der; done
rm -f root.key.der int.key.der

