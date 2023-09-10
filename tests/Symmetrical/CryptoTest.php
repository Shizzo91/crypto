<?php

    namespace Crypto\Test\Symmetrical;

    use Crypto\Symmetrical\SymmetricalCrypto;
    use PHPUnit\Framework\TestCase;

    class CryptoTest extends TestCase
    {
        public static function generateRandomString($length = 10): string
        {
            $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
            $charactersLength = strlen($characters);
            $randomString = '';
            for ($i = 0; $i < $length; $i++) {
                $randomString .= $characters[random_int(0, $charactersLength - 1)];
            }
            return $randomString;
        }
        public static $password;
        protected function setUp(): void
        {
            parent::setUp();
            try {
                self::$password = self::generateRandomString(random_int(10, 25));
            } catch (\Exception $e) {
                self::$password = self::generateRandomString(22);
            }
        }


        /**
         * @dataProvider dataProvider
         */
        public function testEncode(string $value): void
        {
            $crypto = new SymmetricalCrypto(self::$password);
            self::assertIsString($crypto->encode($value));
        }

        /**
         * @dataProvider dataProvider
         */
        public function testEncodeString(string $value): void
        {
            $crypto = new SymmetricalCrypto(self::$password);
            self::assertMatchesRegularExpression("/[-A-Za-z0-9+\/=]+/", $crypto->encode($value));
        }

        /**
         * @dataProvider dataProvider
         */
        public function testDecode(string $value): void
        {
            $crypto = new SymmetricalCrypto(self::$password);
            $encoded = $crypto->encode($value);
            self::assertSame($value, $crypto->decode($encoded));
        }

        public static function dataProviderRaw(): \Generator
        {
            try {
                $length = random_int(10, 25);
            } catch (\Exception $e) {
                $length = 22;
            }
            for ($i = 0; $i < $length; $i++) {
                try {
                    $value = self::generateRandomString(random_int(10, 55));
                } catch (\Exception $e) {
                    $value = self::generateRandomString(30);
                }
                yield "index-{$i}" => [$value];
            }
        }

        public static function dataProvider(): array
        {
            return iterator_to_array(self::dataProviderRaw());
        }

    }
