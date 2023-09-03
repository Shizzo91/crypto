# Crypto

## create a RSA key

```bash
# Private key generation (with passphrase)
openssl req -new -nodes -sha512 -newkey rsa:2048 -keyout private.pem 
# Private key generation (without passphrase)
openssl req -nodes -new -x509 -keyout private.pem 
# Public key extraction
openssl rsa -in private.pem -pubout -out public.pem
```