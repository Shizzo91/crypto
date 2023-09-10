<?php

    namespace Crypto\Test\Asymmetric;

    use Crypto\Asymmetric\DoubleCrypto;
    use PHPUnit\Framework\TestCase;

    class DoubleCryptoTest extends TestCase
    {

        /**
         * @dataProvider keyProvider
         */
        public function testCreate(
            string $publicKey,
            string $privateKey,
            ?string $passphrase
        ): void
        {
            $doubleCrypto = DoubleCrypto::create($publicKey, $privateKey, $passphrase);
            self::assertInstanceOf(DoubleCrypto::class, $doubleCrypto);
        }

        /**
         * @dataProvider keyProvider
         */
        public function testEncode(
            string $publicKey,
            string $privateKey,
            ?string $passphrase
        ): void
        {
            $doubleCrypto = DoubleCrypto::create($publicKey, $privateKey, $passphrase);
            self::assertIsString($doubleCrypto->encode("hallo"));
        }
        /**
         * @dataProvider keyProvider
         */
        public function testEncodeString(
            string $publicKey,
            string $privateKey,
            ?string $passphrase
        ): void
        {
            $doubleCrypto = DoubleCrypto::create($publicKey, $privateKey, $passphrase);
            self::assertMatchesRegularExpression("/[-A-Za-z0-9+\/=]+/", $doubleCrypto->encode("hallo"));
        }

        /**
         * @dataProvider decodeKeyProvider
         */
        public function testDecode(
            string $public2,
            string $private1,
            ?string $passphrase1,
            string $public1,
            string $private2,
            ?string $passphrase2
        ): void
        {
            $data = "hello world";
            $startDouble = DoubleCrypto::create($public2, $private1, $passphrase1);
            $endDouble = DoubleCrypto::create($public1, $private2, $passphrase2);

            $encode = $startDouble->encode($data);

            self::assertSame($data, $endDouble->decode($encode));
        }

        public static function decodeKeyProvider(): \Generator
        {

            $chunks = array_chunk(self::keyProvider(), 2);
            foreach ($chunks as $i => $chunk) {
                $index = "";
                switch ($i) {
                    case 0:
                        $index = "key-only";
                        break;
                    case 1:
                        $index = "key-mix-1";
                        break;
                    case 2:
                        $index = "key-mix-2";
                        break;
                    case 3:
                        $index = "key-text";
                        break;
                }



                yield $index."-1" => array_merge(...$chunk);
                yield $index."-2" => array_merge(...array_reverse($chunk));
            }

        }

        public static function keyProvider(): array
        {
            $private1 = dirname(__DIR__, 2)."/private.pem";
            $public1 = dirname(__DIR__, 2)."/public.pem";
            $private2 = dirname(__DIR__, 2)."/private-2.pem";
            $public2 = dirname(__DIR__, 2)."/public-2.pem";
            $passphrase2 = "hallo";
            return [
                // key only
                "key-only-1" => [
                    $public2,
                    $private1,
                    null,
                ],
                "key-only-2" => [
                    $public1,
                    $private2,
                    $passphrase2,
                ],

                // mix keys
                "key-mix-1-1" => [
                    file_get_contents($public2),
                    $private1,
                    null,
                ],

                "key-mix-2-1" => [
                    file_get_contents($public1),
                    $private2,
                    $passphrase2,
                ],

                "key-mix-1-2" => [
                    $public2,
                    file_get_contents($private1),
                    null,
                ],

                "key-mix-2-2" => [
                    $public1,
                    file_get_contents($private2),
                    $passphrase2,
                ],

                // text
                "key-text-1" => [
                    file_get_contents($public2),
                    file_get_contents($private1),
                    null,
                ],
                "key-text-2" => [
                    file_get_contents($public1),
                    file_get_contents($private2),
                    $passphrase2,
                ],
            ];
        }
    }
