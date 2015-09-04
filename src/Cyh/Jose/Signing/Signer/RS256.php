<?php
namespace Cyh\Jose\Signing\Signer;

class RS256 extends RSA
{
    public function getAlg()
    {
        return 'RS256';
    }

    public function getHashAlgorithm()
    {
        return OPENSSL_ALGO_SHA256;
    }
}
