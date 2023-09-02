<?php

    namespace Crypto\Asymmetric;

    use Crypto\Helper\CryptoException;
    use Crypto\Helper\CryptoInterface;

    class PublicSimpleCrypto implements CryptoInterface
    {
        protected string $publicKey;

        /**
         * @throws CryptoException
         */
        public function __construct(
            string $publicKey
        )
        {
            if (!preg_match("/^([-A-z ]+)\r*\n/m", $publicKey)) {
                if (!is_file($publicKey)) {
                    throw new CryptoException("public key file not found \"{$publicKey}\"", 201);
                }
                $publicKey = "file://{$publicKey}";
            }
            $this->publicKey = $publicKey;
        }

        /**
         * gets the OpenSSLAsymmetricKey ot this instance or throws a CryptoException in case of fail
         *
         * @return \OpenSSLAsymmetricKey
         * @throws CryptoException
         */
        protected function getKey(): \OpenSSLAsymmetricKey
        {
            $key = openssl_get_publickey($this->publicKey);
            if (!$key instanceof \OpenSSLAsymmetricKey) {
                throw new CryptoException("failed to create open ssl key", 202);
            }
            return $key;
        }

        /**
         * encoding the data with the public key and reruns a base64 string back or throws a CryptoException in case of failing the process
         *
         * @param string|\Stringable $data - data that has to encoded
         * @return string - base64 string
         * @throws CryptoException
         */
        public function encode(string|\Stringable $data): string
        {
            $output = "";
            $encodeProcess = openssl_public_encrypt(
                (string) $data,
                $output,
                $this->getKey(),
                OPENSSL_SSLV23_PADDING
            );
            if (!$encodeProcess) {
                throw new CryptoException("fail to encode", 203);
            }
            return base64_encode($output);
        }

        /**
         * decoding the base64Cipher with the private key and reruns a string back or throws a CryptoException in case of failing the process
         *
         * @param string $base64Cipher
         * @return string
         * @throws CryptoException
         */
        public function decode(string $base64Cipher): string
        {
            $cipher = base64_decode($base64Cipher);
            if (!is_string($cipher)) {
                throw new CryptoException("fail to encode base64", 204);
            }

            $output = "";
            $decryptProcess = openssl_public_decrypt(
                $cipher,
                $output,
                $this->getKey()
            );
            if (!$decryptProcess) {
                throw new CryptoException("fail to decode", 205);
            }
            return $output;
        }

    }