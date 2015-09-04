<?php
namespace Cyh\Jose\Signing\Signer;

class None implements SignerInterface
{
    /**
     * @param string $message
     * @param string $secret_key
     * @param string $pass_phrase default null
     * @return string
     */
    public function sign($message, $secret_key, $pass_phrase=null)
    {
        return '';
    }

    /**
     * @param string $message
     * @param string $signature
     * @param string $secret_key
     * @return bool
     */
    public function verify($message, $signature, $secret_key)
    {
        return true;
    }

    /**
     * @return string
     */
    public function getHashAlgorithm()
    {
        return '';
    }

    /**
     * @return string
     */
    public function getAlg()
    {
        return 'none';
    }
}
