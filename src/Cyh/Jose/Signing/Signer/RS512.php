<?php
namespace Cyh\Jose\Signing\Signer;

class RS512 extends RSA
{
    public function getAlg()
    {
        return 'RS512';
    }

    public function getHashAlgorithm()
    {
        return OPENSSL_ALGO_SHA512;
    }
}
