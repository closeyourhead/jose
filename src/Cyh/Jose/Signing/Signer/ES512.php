<?php
namespace Cyh\Jose\Signing\Signer;

class ES512 extends ECDSA
{
    public function getAlg()
    {
        return 'ES512';
    }

    public function getHashAlgorithm()
    {
        return OPENSSL_ALGO_SHA512;
    }
}
