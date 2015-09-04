<?php

use Cyh\Jose\Utils\Json;

class JsonTest extends PHPUnit_Framework_TestCase
{
    public function testEncodeDecodeJsonSuccess()
    {
        $original = array(
            'foo' => 'bar',
            'text' => 'テキスト',
            'url' => 'http://www.example.com'
        );

        $json = Json::encode($original);
        $this->assertJson($json, 'invalid json');

        $decoded = Json::decode($json);

        $this->assertEquals($original, $decoded);
    }

    /**
     * @expectedException Cyh\Jose\Exception\UnexpectedValueException
     */
    public function testDecodeJsonInvalidParam()
    {
        Json::decode('{abc}');
    }

    public function testEncodeJsonInvalidParam()
    {
        if (version_compare(PHP_VERSION, '5.5.0', '>=')) {
            $deep_array = array();
            $depth = 0;
            $deep_array = $this->_nestArray($deep_array, $depth);
            $depth = 0;
            $deep_array = $this->_nestArray($deep_array, $depth);
            $depth = 0;
            $deep_array = $this->_nestArray($deep_array, $depth);

            $this->setExpectedException('Cyh\Jose\Exception\UnexpectedValueException');
            Json::encode($deep_array);
        }
    }

    private function _nestArray($arr, &$depth)
    {
        if ($depth > 200) {
            return $arr;
        }
        $result = array($arr);
        $depth++;
        return $this->_nestArray($result, $depth);
    }
}
