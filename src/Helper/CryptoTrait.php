<?php

    namespace Crypto\Helper;

    trait CryptoTrait
    {
        /**
         * @param string $data
         * @return string
         * @throws CryptoException
         */
        public function encodeAsBase64(string $data): string
        {
            return base64_encode($this->encode($data));
        }

        /**
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