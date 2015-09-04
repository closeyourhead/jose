<?php
namespace Cyh\Jose\Encryption\Enc;

class A128CBC_HS256 extends AES_CBC_HS
{
    /**
     * @return string
     */
    public function getEnc()
    {
        return 'A128CBC-HS256';
    }

    /**
     * @return string
     */
    public function getMethod()
    {
        return 'aes-128-cbc';
    }

    /**
     * @return string
     */
    public function getHashAlgorithm()
    {
        return 'sha256';
    }
}
