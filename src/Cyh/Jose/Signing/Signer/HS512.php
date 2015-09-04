<?php
namespace Cyh\Jose\Signing\Signer;

class HS512 extends HMAC
{
    public function getAlg()
    {
        return 'HS512';
    }

    public function getHashAlgorithm()
    {
        return 'sha512';
    }
}
