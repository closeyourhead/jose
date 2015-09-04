<?php
namespace Cyh\Jose\Signing\Signer;

class ES256 extends ECDSA
{
    public function getAlg()
    {
        return 'ES256';
    }

    public function getHashAlgorithm()
    {
        return OPENSSL_ALGO_SHA256;
    }
}
