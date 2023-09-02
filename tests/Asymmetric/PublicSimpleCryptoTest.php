<?php

    namespace Crypto\Test\Asymmetric;

    use Crypto\Helper\CryptoException;
    use Crypto\Asymmetric\PrivateSimpleCrypto;
    use Crypto\Asymmetric\PublicSimpleCrypto;
    use PHPUnit\Framework\TestCase;

    class PublicSimpleCryptoTest extends TestCase
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
            $publicCrypto = new PublicSimpleCrypto(self::$publicKey);
            self::assertInstanceOf("Crypto\Asymmetric\PublicSimpleCrypto", $publicCrypto);
        }

        public function testFileNotFound(): void
        {
            $publicKey = self::$fakePublicKey;
            $this->expectExceptionObject(new CryptoException("public key file not found \"{$publicKey}\"", 201));
            $publicCrypto = new PublicSimpleCrypto($publicKey);
        }

        /**
         * @dataProvider keyProvider
         */
        public function testEncode(string $publicKey): void
        {
            $publicCrypto = new PublicSimpleCrypto($publicKey);
            self::assertIsString($publicCrypto->encode("hallo"));
        }

        /**
         * @dataProvider keyProvider
         */
        public function testEncodeString(string $publicKey): void
        {
            $publicCrypto = new PublicSimpleCrypto($publicKey);
            self::assertMatchesRegularExpression("/[-A-Za-z0-9+\/=]+/", $publicCrypto->encode("hallo"));
        }

        /**
         * @dataProvider keyProvider
         */
        public function testDecodeString(string $publicKey): void
        {
            $data = "hallo";
            $privateCrypto = new PrivateSimpleCrypto(self::$privateKey);
            $publicCrypto = new PublicSimpleCrypto($publicKey);
            $encode = $privateCrypto->encode($data);
            self::assertSame($data, $publicCrypto->decode($encode));
        }


        public static function keyProvider(): array
        {
            $key = dirname(__DIR__, 2)."/public.pem";
            return [
                "key" => [$key],
                "string" => [file_get_contents($key)]
            ];
        }
    }
