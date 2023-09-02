<?php

    namespace Crypto\Helper;

    interface CryptoInterface
    {

        public function encode(string|\Stringable $data): string;

        public function decode(string $base64Cipher): string;

    }