<?php

    namespace Crypto\Single;

    use Crypto\Helper\CryptoError;
    use Crypto\Helper\CryptoInterface;

    class PublicCrypto implements CryptoInterface
    {
        protected string $publicKey;
        public function __construct(
            string $publicKey
        )
        {
            if (!preg_match("/^([-A-z ]+)\r*\n/m", $publicKey)) {
                if (!is_file($publicKey)) throw new CryptoError("public key file not found \"{$publicKey}\"");
                $publicKey = "file://{$publicKey}";
            }
            $this->publicKey = $publicKey;
        }

        private function getKey(): \OpenSSLAsymmetricKey
        {
            $key = openssl_get_publickey($this->publicKey);
            if (!is_a($key, "OpenSSLAsymmetricKey")) throw new CryptoError("");
            return $key;
        }

        public function encode(string|\Stringable $data): string
        {
            $output = "";
            $encodeProcess = openssl_public_encrypt(
                (string) $data,
                $output,
                $this->getKey(),
                OPENSSL_SSLV23_PADDING
            );
            if (!$encodeProcess) throw new CryptoError("");
            return base64_encode($output);
        }

        public function decode(string $base64Cipher): string
        {
            $cipher = base64_decode($base64Cipher);
            if (!is_string($cipher)) throw new CryptoError("");

            $output = "";
            $decryptProcess = openssl_public_decrypt(
                $cipher,
                $output,
                $this->getKey()
            );
            if (!$decryptProcess) throw new CryptoError("");
            return $output;
        }

    }