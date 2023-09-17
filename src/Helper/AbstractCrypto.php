<?php

    namespace Crypto\Helper;

    abstract class AbstractCrypto
    {
        /**
         * max encrypt block size
         *
         * @var int
         */
        public const ENCRYPT_BLOCK_SIZE = 200;

        /**
         * max decrypt block size
         *
         * @var int
         */
        public const DECRYPT_BLOCK_SIZE = 256;

        /**
         * define the encode function
         *
         * @param string $data
         * @return string
         */
        abstract public function encode(string $data): string;

        /**
         * define the decode function
         *
         * @param string $cipher
         * @return string
         */
        abstract public function decode(string $cipher): string;

        /**
         * uses encode function and returns it as base64 string
         *
         * @param string $data
         * @return string
         * @throws CryptoException
         */
        public function encodeAsBase64(string $data): string
        {
            return base64_encode($this->encode($data));
        }

        /**
         * uses encode function and gzip it
         *
         * @param string $data
         * @param int $level
         * @param int $encoding
         * @return string
         * @throws CryptoException
         */
        public function encodeAsGzip(
            string $data,
            int $level = -1,
            int $encoding = ZLIB_ENCODING_DEFLATE
        ): string
        {
            $gzipCipher = gzcompress($this->encode($data), $level, $encoding);
            if (!is_string($gzipCipher)) {
                throw new CryptoException("fail to encode to gzip", 1);
            }

            return $gzipCipher;
        }

        /**
         * uses encode function, gzip it and returns it as base64 string
         *
         * @param string $data
         * @param int $level
         * @param int $encoding
         * @return string
         * @throws CryptoException
         */
        public function encodeAsGzipBase64(
            string $data,
            int $level = -1,
            int $encoding = ZLIB_ENCODING_DEFLATE
        ): string
        {
            return base64_encode($this->encodeAsGzip($data, $level, $encoding));
        }

        /**
         * uses decode function it from a base64 string
         *
         * @param string $base64Cipher
         * @return string
         * @throws CryptoException
         */
        public function decodeFromBase64(string $base64Cipher): string
        {
            $cipher = base64_decode($base64Cipher);
            if (!is_string($cipher)) {
                throw new CryptoException("fail to encode base64", 2);
            }
            return $this->decode($cipher);
        }

        /**
         * uses decode function it from a gzip binary string
         *
         * @param string $cipherGzip
         * @param int $maxLength
         * @return string
         * @throws CryptoException
         */
        public function decodeFromGzip(
            string $cipherGzip,
            int $maxLength = 0
        ): string
        {
            $cipher = gzuncompress($cipherGzip, $maxLength);

            if (!is_string($cipher)) {
                throw new CryptoException("fail to encode gzip", 3);
            }

            return $this->decode($cipher);
        }

        /**
         * uses decode function it from a gzip base64 string
         *
         * @param string $base64Cipher
         * @param int $maxLength
         * @return string
         * @throws CryptoException
         */
        public function decodeFromGzipBase64(
            string $base64Cipher,
            int $maxLength = 0
        ): string
        {
            $cipherGzip = base64_decode($base64Cipher, $maxLength);
            if (!is_string($cipherGzip)) {
                throw new CryptoException("fail to encode gzip base64", 4);
            }
            return $this->decodeFromGzip($cipherGzip)    ;
        }

    }