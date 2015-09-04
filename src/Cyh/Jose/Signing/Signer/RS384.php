<?php
namespace Cyh\Jose\Signing\Signer;

class RS384 extends RSA
{
    public function getAlg()
    {
        return 'RS384';
    }

    public function getHashAlgorithm()
    {
        return OPENSSL_ALGO_SHA384;
    }
}
