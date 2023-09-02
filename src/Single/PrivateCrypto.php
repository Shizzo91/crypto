<?php

    namespace Crypto\Single;

    use Crypto\Helper\CryptoException;
    use Crypto\Helper\CryptoInterface;

    class PrivateCrypto implements CryptoInterface
    {
        protected string $privateKey;

        /**
         * @throws CryptoException
         */
        public function __construct(
            string $privateKey,
            protected ?string $passphrase = null
        ){
            if (!preg_match("/^([-A-z ]+)\r*\n/m", $privateKey)) {
                if (!is_file($privateKey)) {
                    throw new CryptoException("private key file not found \"{$privateKey}\"");
                }
                $privateKey = "file://{$privateKey}";
            }
            $this->privateKey = $privateKey;
        }

        /**
         * gets the OpenSSLAsymmetricKey ot this instance or throws a CryptoException in case of fail
         * @return \OpenSSLAsymmetricKey
         * @throws CryptoException
         */
        private function getKey(): \OpenSSLAsymmetricKey
        {
            $key = openssl_pkey_get_private($this->privateKey, $this->passphrase);
            if (!$key instanceof \OpenSSLAsymmetricKey) {
                //TODO: add exception message
                throw new CryptoException("");
            }
            return $key;
        }

        /**
         * encoding the data with the private key and reruns a base64 string back or throws a CryptoException in case of failing the process
         * @param string|\Stringable $data - data that has to encoded
         * @return string - base64 string
         * @throws CryptoException
         */
        public function encode(string|\Stringable $data): string
        {
            $output = "";
            $encodeProcess = openssl_private_encrypt(
                (string) $data,
                $output,
                $this->getKey()
            );
            if (!$encodeProcess) {
                //TODO: add exception message
                throw new CryptoException("");
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
                //TODO: add exception message
                throw new CryptoException("");
            }

            $output = "";
            $decryptProcess = openssl_private_decrypt(
                $cipher,
                $output,
                $this->getKey()
            );
            if (!$decryptProcess) {
                //TODO: add exception message
                throw new CryptoException("");
            }
            return $output;
        }
    }