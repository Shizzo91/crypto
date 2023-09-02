<?php

    namespace Crypto\Test\Single;

    use Crypto\Helper\CryptoException;
    use Crypto\Single\PrivateCrypto;
    use PHPUnit\Framework\TestCase;

    class PrivateCryptoTest extends TestCase
    {
        public function testFileFound(): void
        {
            $private = new PrivateCrypto("../../private.pem");
            self::assertInstanceOf("Crypto\Single\PrivateCrypto", $private);
        }

        public function testFileNotFound(): void
        {
            $privateKey = "../../private.pe";
            $this->expectExceptionObject(new CryptoException("private key file not found \"{$privateKey}\""));
            $private = new PrivateCrypto($privateKey);
        }

        public function testEnc(): void
        {
            $privateCrypto = new PrivateCrypto("../../private.pem");
            self::assertIsString($privateCrypto->encode("hallo"));
        }
    }
