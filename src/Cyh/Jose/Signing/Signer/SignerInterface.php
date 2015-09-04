<?php
namespace Cyh\Jose\Signing\Signer;

use Cyh\Jose\Signing\Exception\InvalidSignatureException;

interface SignerInterface
{
    /**
     * @param string $message
     * @param mixed $key
     * @param string $pass_phrase default null
     * @return string
     * @throws InvalidSignatureException
     */
    public function sign($message, $key, $pass_phrase=null);

    /**
     * @param string $message
     * @param string $signature
     * @param mixed $key
     * @return true
     * @throws InvalidSignatureException
     */
    public function verify($message, $signature, $key);

    /**
     * @return mixed
     */
    public function getHashAlgorithm();

    /**
     * @return string
     */
    public function getAlg();
}
