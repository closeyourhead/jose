<?php
namespace Cyh\Jose\Signing\Signer;

use Cyh\Jose\Signing\Exception\UnexpectedValueException;
use Cyh\Jose\Signing\Exception\InvalidSignatureException;

abstract class PublicKey implements SignerInterface
{
    /**
     * @param resource $private_or_public_key_resource
     * @return bool
     * @throws UnexpectedValueException
     */
    abstract protected function validateKey($private_or_public_key_resource);

    /**
     * Generate signature
     *
     * @link http://php.net/manual/en/function.openssl-sign.php
     *
     * @param string $message
     * @param resource|string $private_key
     * @param string $pass_phrase default null
     * @return string
     * @throws InvalidSignatureException
     */
    public function sign($message, $private_key, $pass_phrase=null)
    {
        if (!is_resource($private_key)) {
            $private_key = openssl_pkey_get_private($private_key, $pass_phrase);
            if (!is_resource($private_key)) {
                throw new UnexpectedValueException('Unable to load private key: ' . openssl_error_string());
            }
        }

        $this->validateKey($private_key);

        $signature = '';
        $success = openssl_sign($message, $signature, $private_key, $this->getHashAlgorithm());
        if (true === $success) {
            return $signature;
        }

        throw new InvalidSignatureException('Unable to sign data: ' . openssl_error_string());
    }

    /**
     * Verify signature
     *
     * @link http://php.net/manual/en/function.openssl-verify.php
     *
     * @param string $message
     * @param string $signature
     * @param resource|string $public_key
     * @return bool
     * @throws InvalidSignatureException
     */
    public function verify($message, $signature, $public_key)
    {
        if (!is_resource($public_key)) {
            $public_key = openssl_pkey_get_public($public_key);
            if (!is_resource($public_key)) {
                throw new UnexpectedValueException('Unable to load public key: ' . openssl_error_string());
            }
        }

        $this->validateKey($public_key);

        $success = openssl_verify($message, $signature, $public_key, $this->getHashAlgorithm());
        if (1 === $success) {
            return true;
        }

        throw new InvalidSignatureException('Unable verify signature: ' . openssl_error_string());
    }
}
