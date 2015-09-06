<?php
namespace Cyh\Jose\Signing\Signer;

interface SignerInterface
{
    /**
     * @param string $message
     * @param mixed $key
     * @param string $pass_phrase default null
     * @return string
     * @throws \Cyh\Jose\Signing\Exception\InvalidSignatureException
     */
    public function sign($message, $key, $pass_phrase=null);

    /**
     * @param string $message
     * @param string $signature
     * @param mixed $key
     * @return bool true only
     * @throws \Cyh\Jose\Signing\Exception\InvalidSignatureException
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
