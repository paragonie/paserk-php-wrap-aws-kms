<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Operations\Wrap;

use Aws\Kms\KmsClient;
use Exception;
use ParagonIE\Paserk\{Operations\WrapInterface, PaserkException, Util};
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\Paseto\KeyInterface;
use ParagonIE\Paseto\ProtocolInterface;
use ParagonIE\Paseto\Keys\Base\{
    AsymmetricSecretKey,
    SymmetricKey
};

class AwsKms implements WrapInterface
{
    public function __construct(
        protected KmsClient $kmsClient,
        protected ProtocolInterface $pasetoProtocol,
        protected string $keyId,
        protected array $encryptionContext = [],
    ) {}

    public static function customId(): string
    {
        return 'aws-kms';
    }

    public function getProtocol(): ProtocolInterface
    {
        return $this->pasetoProtocol;
    }

    public function wrapKey(string $header, KeyInterface $key): string
    {
        $response = $this->kmsClient->encrypt([
            'KeyId' =>
                $this->keyId,
            'Plaintext' =>
                $key->raw(),
            /* Always set the PaserkHeader key */
            'EncryptionContext' =>
                ['PaserkHeader' => $header] + $this->encryptionContext
        ]);
        return Base64UrlSafe::encodeUnpadded($response['CiphertextBlob']);
    }

    /**
     * @param string $wrapped
     * @return KeyInterface
     *
     * @throws PaserkException
     * @throws Exception
     */
    public function unwrapKey(string $wrapped): KeyInterface
    {
        $pieces = explode('.', $wrapped);
        $version = Util::getPasetoVersion($pieces[0]);
        $ciphertext = Base64UrlSafe::decodeNoPadding($pieces[3]);
        $this->throwIfVersionsMismatch($version);

        $header = implode('.', array_slice($pieces, 0, 3)) . '.';
        if (!hash_equals($pieces[2], self::customId())) {
            throw new PaserkException('Key is not wrapped with the PIE key-wrapping protocol');
        }

        // Call KMS to get the plaintext
        $response = $this->kmsClient->decrypt([
            'KeyId' =>
                $this->keyId,
            'CiphertextBlob' =>
                $ciphertext,
            /* Always set the PaserkHeader key */
            'EncryptionContext' =>
                ['PaserkHeader' => $header] + $this->encryptionContext
        ]);
        $bytes = $response['Plaintext'];

        // Once we've decoded the bytes correctly, initialize the key object.
        if (hash_equals($pieces[1], 'local-wrap')) {
            return new SymmetricKey($bytes, $version);
        }
        if (hash_equals($pieces[1], 'secret-wrap')) {
            return AsymmetricSecretKey::newVersionKey($bytes, $version);
        }

        // Final step: Abort if unknown wrapping type.
        throw new PaserkException('Unknown wrapping type: ' . $pieces[1]);
    }

    public function setEncryptionContext(array $encryptionContext = []): static
    {
        $this->encryptionContext = $encryptionContext;
        return $this;
    }

    /**
     * @param ProtocolInterface $given
     * @throws PaserkException
     */
    private function throwIfVersionsMismatch(ProtocolInterface $given): void
    {
        $expect = $this->getProtocol();
        if (!hash_equals($expect::header(), $given::header())) {
            throw new PaserkException('Invalid key version.');
        }
    }
}
