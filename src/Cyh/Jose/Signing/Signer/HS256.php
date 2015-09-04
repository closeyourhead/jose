<?php
namespace Cyh\Jose\Signing\Signer;

class HS256 extends Hmac
{
    public function getAlg()
    {
        return 'HS256';
    }

    public function getHashAlgorithm()
    {
        return 'sha256';
    }
}
