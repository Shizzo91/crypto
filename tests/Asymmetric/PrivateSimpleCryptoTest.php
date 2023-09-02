<?php

    namespace Crypto\Test\Asymmetric;

    use Crypto\Helper\CryptoException;
    use Crypto\Asymmetric\PrivateSimpleCrypto;
    use Crypto\Asymmetric\PublicSimpleCrypto;
    use PHPUnit\Framework\TestCase;

    class PrivateSimpleCryptoTest extends TestCase
    {
        public static string $privateKey;
        public static string $publicKey;
        public static string $fakePrivateKey;
        public static string $fakePublicKey;
        protected function setUp(): void
        {
            parent::setUp();
            self::$privateKey = dirname(__DIR__, 2)."/private.pem";
            self::$publicKey = dirname(__DIR__, 2)."/public.pem";
            self::$fakePrivateKey = dirname(__DIR__, 2)."/private.pe";
            self::$fakePublicKey = dirname(__DIR__, 2)."/public.pe";
        }

        public function testFileFound(): void
        {
            $private = new PrivateSimpleCrypto(self::$privateKey);
            self::assertInstanceOf("Crypto\Asymmetric\PrivateSimpleCrypto", $private);
        }

        public function testFileNotFound(): void
        {
            $privateKey = self::$fakePrivateKey;
            $this->expectExceptionObject(new CryptoException("private key file not found \"{$privateKey}\"", 101));
            $private = new PrivateSimpleCrypto($privateKey);
        }

        /**
         * @dataProvider keyProvider
         */
        public function testEncode(string $privateKey): void
        {
            $privateCrypto = new PrivateSimpleCrypto($privateKey);
            self::assertIsString($privateCrypto->encode("hallo"));
        }

        /**
         * @dataProvider keyProvider
         */
        public function testEncodeString(string $privateKey): void
        {
            $privateCrypto = new PrivateSimpleCrypto($privateKey);
            self::assertMatchesRegularExpression("/[-A-Za-z0-9+\/=]+/", $privateCrypto->encode("hallo"));
        }

        /**
         * @dataProvider keyProvider
         */
        public function testDecodeString(string $privateKey): void
        {
            $data = "hallo";
            $privateCrypto = new PrivateSimpleCrypto($privateKey);
            $publicCrypto = new PublicSimpleCrypto(self::$publicKey);
            $encode = $publicCrypto->encode($data);
            self::assertSame($data, $privateCrypto->decode($encode));
        }

        public static function keyProvider(): array
        {
            $key = dirname(__DIR__, 2)."/private.pem";
            return [
                "key" => [$key],
                "string" => [file_get_contents($key)]
            ];
        }
    }
