<?php
namespace Cyh\Jose\Encryption\Alg;

abstract class RSA implements AlgInterface
{
    /**
     * @return int
     */
    abstract protected function getPaddingType();

    /**
     * @param string $cek
     * @param string $public_key
     * @return string
     * @throws \Exception
     */
    public function encrypt($cek, $public_key)
    {
        $encrypted_cek = null;
        if (openssl_public_encrypt($cek, $encrypted_cek, $public_key, $this->getPaddingType())) {
            return $encrypted_cek;
        }

        throw new \Exception('Unable to encrypt cek: ' . openssl_error_string());
    }

    /**
     * @param string $encrypted_cek
     * @param string $private_key
     * @param string $pass_phrase default null
     * @return string
     * @throws \Exception
     */
    public function decrypt($encrypted_cek, $private_key, $pass_phrase=null)
    {
        $decrypted_cek = null;
        $pk = openssl_get_privatekey($private_key, $pass_phrase);
        if (openssl_private_decrypt($encrypted_cek, $decrypted_cek, $pk, $this->getPaddingType())) {
            return $decrypted_cek;
        }

        throw new \Exception('Unable to decrypt cek: ' . openssl_error_string());
    }
}
