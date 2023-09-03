# Crypto

## Symmetrical

### usage
```php
    // encoding
    $password = "password";
    $symmetricalCrypto = new SymmetricalCrypto($password);
    $encoded = $symmetricalCrypto->encode("Stringable or string"); 

    // decoding
    $password = "password";
    $symmetricalCrypto = new SymmetricalCrypto($password);
    $decode = $symmetricalCrypto->decode($encoded); 
```


## Asymmetric or Hybrid

### create a RSA key

```bash
# Private key generation (with passphrase)
openssl req -new -nodes -sha512 -newkey rsa:2048 -keyout private.pem 
# Private key generation (without passphrase)
openssl req -nodes -new -x509 -keyout private.pem 
# Public key extraction
openssl rsa -in private.pem -pubout -out public.pem
```

### usage for simple asymmetric

```php

    $privateSimpleCrypto = new PrivateSimpleCrypto(
        "../private-2.pem", // file or text
        "passphrase" // passphrase optional
    );
    $encoded = $privateSimpleCrypto->encode("Stringable or string"); 

    $publicSimpleCrypto = new PublicSimpleCrypto(
        "../public-2.pem" // file or text
    );
    $decode = $publicSimpleCrypto->decode($encoded); 

```

### usage for double asymmetric

```php
    // simple
    // encoding
    $privateSimpleCrypto = new PrivateSimpleCrypto(
        "../private-2.pem", // file or text
        "passphrase" // passphrase optional
    );
    $encoded = $privateSimpleCrypto->encode("Stringable or string"); 
    
    // decoding
    $publicSimpleCrypto = new PublicSimpleCrypto(
        "../public-2.pem" // file or text
    );
    $decode = $publicSimpleCrypto->decode($encoded); 
    
    // double
    // encoding
    $myPrivateKey = new PrivateSimpleCrypto("../private.pem");
    $receiverPublicKey = new PublicSimpleCrypto("../public-2.pem");
    $doubleCrypto = new DoubleCrypto(
        $receiverPublicKey,
        $myPrivateKey
    );
    $encoded = $doubleCrypto->encode("Stringable or string"); 

    
    // decoding
    // with text as key
    $receiverPrivateKey = "-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----";
    $myPublicKey = "../public.pem";

    $doubleCryptoReceiver = DoubleCrypto::create($myPublicKey, $receiverPrivateKey, "secret");
    $decoded = $doubleCryptoReceiver->decode($encoded);
    var_dump($decoded); // "Stringable or string"

```

### usage for hybrid

```php
    // simple
    // encoding
    $simpleHybridPrivate = HybridCrypto::createPrivateSimple("password", "../private.pem");
    $encoded = $simpleHybridPrivate->encode("Stringable or string");

    // decoding
    $simpleHybridPublic = HybridCrypto::createPublicSimple("password", "../public.pem");
    $decoded = $simpleHybridPublic->encode($encoded);

    // double
    // encoding
    $doubleHybridTransmitter = HybridCrypto::createDouble(
        "password",
        "../public-2.pem",
        "../private.pem"
    );
    $encoded = $doubleHybridTransmitter->encode("Stringable or string");

    // decoding
    $doubleHybridReceiver = HybridCrypto::createDouble(
        "password",
        "../public.pem",
        "../private-2.pem",
        "passphrase"
    );
    $decoded = $doubleHybridReceiver->encode($encoded);

```