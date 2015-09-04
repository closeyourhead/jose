<?php
namespace Cyh\Jose\Encryption\Alg;

class RSA1_5 extends RSA
{
    /**
     * @return string
     */
    public function getAlg()
    {
        return 'RSA1_5';
    }

    /**
     * @return int
     */
    protected function getPaddingType()
    {
        return OPENSSL_PKCS1_PADDING;
    }
}
