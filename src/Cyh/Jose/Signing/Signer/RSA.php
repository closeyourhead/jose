<?php
namespace Cyh\Jose\Signing\Signer;

use Cyh\Jose\Signing\Exception\UnexpectedValueException;

abstract class RSA extends PublicKey
{
    /**
     * @param resource $private_or_public_key_resource
     * @return bool
     * @throws UnexpectedValueException
     */
    protected function validateKey($private_or_public_key_resource)
    {
        $valid_type = OPENSSL_KEYTYPE_RSA;
        $details = openssl_pkey_get_details($private_or_public_key_resource);
        if (!is_array($details) || !isset($details['type']) || $valid_type !== $details['type']) {
            throw new UnexpectedValueException('Invalid key: ' . openssl_error_string());
        }

        return true;
    }
}
