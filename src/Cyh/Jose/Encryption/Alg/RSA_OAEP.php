<?php
namespace Cyh\Jose\Encryption\Alg;

class RSA_OAEP extends RSA
{
    /**
     * @return string
     */
    public function getAlg()
    {
        return 'RSA-OAEP';
    }

    /**
     * @return int
     */
    protected function getPaddingType()
    {
        return OPENSSL_PKCS1_OAEP_PADDING;
    }
}
