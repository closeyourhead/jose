<?php
namespace Cyh\Jose\Signing\Signer;

class HS384 extends HMAC
{
    public function getAlg()
    {
        return 'HS384';
    }

    public function getHashAlgorithm()
    {
        return 'sha384';
    }
}
