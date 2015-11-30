<?php
namespace Cyh\Jose\Signing\Signer;

use Cyh\Jose\Utils\Str;
use Cyh\Jose\Signing\Exception\InvalidSignatureException;

abstract class HMAC implements SignerInterface
{
    /**
     *
     * @link http://php.net/manual/en/function.hash-hmac.php
     *
     * @param string $message
     * @param string $secret_key
     * @param string $pass_phrase default null
     * @return string
     */
    public function sign($message, $secret_key, $pass_phrase=null)
    {
        $hash = hash_hmac($this->getHashAlgorithm(), $message, $secret_key, true);
        if (false !== $hash) {
            return $hash;
        }

        throw new InvalidSignatureException('Unable to sign data');
    }

    /**
     *
     * @link http://php.net/manual/en/function.hash-hmac.php
     * @link http://php.net/manual/en/function.hash-equals.php
     *
     * @param string $message
     * @param string $signature
     * @param string $secret_key
     * @return bool
     * @throws InvalidSignatureException
     */
    public function verify($message, $signature, $secret_key)
    {
        $hash = hash_hmac($this->getHashAlgorithm(), $message, $secret_key, true);

        if (function_exists('hash_equals')) {
            if (true === hash_equals($signature, $hash)) {
                return true;
            }

            throw new InvalidSignatureException('Unable to verify signature');
        }

        if (Str::equals($signature, $hash)) {
            return true;
        }

        throw new InvalidSignatureException('Unable to verify signature');
    }
}
