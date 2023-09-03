<?php

    namespace Crypto\Asymmetric;

    use Crypto\Helper\CryptoException;
    use Crypto\Helper\CryptoInterface;

    class DoubleCrypto implements CryptoInterface
    {
        /**
         * @param string $publicKey
         * @param string $privateKey
         * @param string|null $passphrase
         * @return self
         * @throws CryptoException
         */
        public static function create(
            string $publicKey,
            string $privateKey,
            ?string $passphrase = null
        ): self
        {
            $publicSimpleCrypto = new PublicSimpleCrypto($publicKey);
            $privateSimpleCrypto = new PrivateSimpleCrypto($privateKey, $passphrase);
            return new self($publicSimpleCrypto, $privateSimpleCrypto);
        }

        public function __construct(
            protected PublicSimpleCrypto $publicSimpleCrypto,
            protected PrivateSimpleCrypto $privateSimpleCrypto
        ){}

        /**
         * @param \Stringable|string $data
         * @return string
         * @throws CryptoException
         */
        public function encode(\Stringable|string $data): string
        {
            $publicEncodeData = $this->publicSimpleCrypto->encode($data);
            return $this->privateSimpleCrypto->encode($publicEncodeData);
        }

        /**
         * @param string $base64Cipher
         * @return string
         * @throws CryptoException
         */
        public function decode(string $base64Cipher): string
        {
            $publicDecodeData = $this->publicSimpleCrypto->decode($base64Cipher);
            return $this->privateSimpleCrypto->decode($publicDecodeData);
        }
    }