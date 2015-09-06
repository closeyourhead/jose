<?php
namespace Cyh\Jose\Encryption\Alg;

use Cyh\Jose\Encryption\Exception\UnexpectedValueException;

abstract class RSA implements AlgInterface
{
    /**
     * @return int
     */
    abstract protected function getPaddingType();

    /**
     * @param string $cek
     * @param string $public_key file:///path/to/key or PEM strings
     * @return string
     * @throws \Cyh\Jose\Encryption\Exception\UnexpectedValueException
     */
    public function encrypt($cek, $public_key)
    {
        $encrypted_cek = null;
        $pub_key_resource = openssl_get_publickey($public_key);
        if (!$pub_key_resource) {
            throw new UnexpectedValueException('Unable to load public key: ' . openssl_error_string());
        }

        $this->validateKey($pub_key_resource);

        // TODO: openssl_public_encrypt is not accept public key resource
        if (openssl_public_encrypt($cek, $encrypted_cek, $public_key, $this->getPaddingType())) {
            return $encrypted_cek;
        }

        throw new UnexpectedValueException('Unable to encryption cek: ' . openssl_error_string());
    }

    /**
     * @param string $encrypted_cek
     * @param string $private_key file:///path/to/key or PEM strings
     * @param string $pass_phrase default null
     * @return string
     * @throws \Cyh\Jose\Encryption\Exception\UnexpectedValueException
     */
    public function decrypt($encrypted_cek, $private_key, $pass_phrase=null)
    {
        $decrypted_cek = null;
        $prv_key_resource = openssl_get_privatekey($private_key, $pass_phrase);
        if (!$prv_key_resource) {
            throw new UnexpectedValueException('Unable to load public key: ' . openssl_error_string());
        }

        $this->validateKey($prv_key_resource);

        if (openssl_private_decrypt($encrypted_cek, $decrypted_cek, $prv_key_resource, $this->getPaddingType())) {
            return $decrypted_cek;
        }

        throw new UnexpectedValueException('Unable to decryption cek: ' . openssl_error_string());
    }

    /**
     * @param resource $private_or_public_key_resource
     * @return bool
     * @throws \Cyh\Jose\Encryption\Exception\UnexpectedValueException
     */
    protected function validateKey($private_or_public_key_resource)
    {
        $details = openssl_pkey_get_details($private_or_public_key_resource);
        if (!is_array($details) || !isset($details['type']) || OPENSSL_KEYTYPE_RSA !== $details['type']) {
            throw new UnexpectedValueException('Invalid key. : ' . openssl_error_string());
        }

        return true;
    }
}
