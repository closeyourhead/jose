<?php
namespace Cyh\Jose\Signing\Signer;

class ES384 extends ECDSA
{
    public function getAlg()
    {
        return 'ES384';
    }

    public function getHashAlgorithm()
    {
        return OPENSSL_ALGO_SHA384;
    }
}
