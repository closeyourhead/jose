<?php
namespace Cyh\Jose\Encryption\Enc;

class A256CBC_HS512 extends AES_CBC_HS
{
    /**
     * @return string
     */
    public function getEnc()
    {
        return 'A256CBC-HS512';
    }

    /**
     * @return string
     */
    public function getMethod()
    {
        return 'aes-256-cbc';
    }

    /**
     * @return string
     */
    public function getHashAlgorithm()
    {
        return 'sha512';
    }
}
