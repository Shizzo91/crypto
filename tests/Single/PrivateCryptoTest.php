<?php

    namespace Crypto\Test\Single;

    use Crypto\Single\PrivateCrypto;
    use PHPUnit\Framework\TestCase;

    class PrivateCryptoTest extends TestCase
    {
        public function testFileFound(): void
        {
            $this->expectExceptionMessage('private key file not found ""');
            $private = new PrivateCrypto("");
        }
    }
