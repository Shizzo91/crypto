<?php

    namespace Crypto\Single;

    use Crypto\Helper\CryptoException;
    use Crypto\Helper\CryptoInterface;

    class PublicCrypto implements CryptoInterface
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
                    throw new CryptoException("public key file not found \"{$publicKey}\"");
                }
                $publicKey = "file://{$publicKey}";
            }
            $this->publicKey = $publicKey;
        }

        /**
         * @throws CryptoException
         */
        private function getKey(): \OpenSSLAsymmetricKey
        {
            $key = openssl_get_publickey($this->publicKey);
            if (!$key instanceof \OpenSSLAsymmetricKey) {
                //TODO: add exception message
                throw new CryptoException("");
            }
            return $key;
        }

        /**
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
                //TODO: add exception message
                throw new CryptoException("");
            }
            return base64_encode($output);
        }

        /**
         * @throws CryptoException
         */
        public function decode(string $base64Cipher): string
        {
            $cipher = base64_decode($base64Cipher);
            if (!is_string($cipher)) {
                throw new CryptoException("");
            }

            $output = "";
            $decryptProcess = openssl_public_decrypt(
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