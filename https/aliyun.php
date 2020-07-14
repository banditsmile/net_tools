<?php
//你的密钥
$accessKeyId = "";
$accessKeySecret = "";
//要解析的域名记录
$records = [
    'goloiov.cn'
];

/**
 *
 *    Sakura DDNS 阿里云 万网 DDNS
 *
 *    GNU General Public License V3
 *
 */
class AliyunDNS {

    public $data;
    public $accessKeyId;
    public $accessKeySecret;
    public $url = "http://alidns.aliyuncs.com/?";
    private $param;

    public function __construct( $KeyId, $KeySecret) {
        $this->accessKeyId = $KeyId;
        $this->accessKeySecret = $KeySecret;

        date_default_timezone_set("GMT");

        $this->data = array(
            'Format' => 'json',
            'Version' => '2015-01-09',
            'AccessKeyId' => $this->accessKeyId,
            'SignatureVersion' => '1.0',
            'SignatureMethod' => 'HMAC-SHA1',
            'Timestamp' => date('Y-m-d\TH:i:s\Z'),
        );
    }

    public function percentEncode($str) {
        $res = urlencode($str);
        $res = preg_replace('/\+/', '%20', $res);
        $res = preg_replace('/\*/', '%2A', $res);
        $res = preg_replace('/%7E/', '~', $res);
        return $res;
    }

    public function computeSignature($parameters, $accessKeySecret) {
        ksort($parameters);
        $canonicalizedQueryString = '';
        foreach($parameters as $key => $value) {
            $canonicalizedQueryString .= '&' . $this->percentEncode($key) . '=' . $this->percentEncode($value);
        }
        $stringToSign = 'GET&%2F&' . $this->percentencode(substr($canonicalizedQueryString, 1));
        $signature = base64_encode(hash_hmac('sha1', $stringToSign, $accessKeySecret . '&', true));
        return $signature;
    }

    public function callInterface() {
        $this->param['SignatureNonce'] = uniqid().time();
        $this->param['Signature'] = $this->computeSignature($this->param, $this->accessKeySecret);
        $request = $this->url . http_build_query($this->param);

        $res = file_get_contents($request);
        return json_decode($res, true);
    }


    /**
     * @param string $domain 要解析的域名
     * @param string $type  记录类型A,txt...
     * @param int $pageNum
     * @param int $pageSize
     * @return bool|string
     */
    public function describeRecords($domain, $type='', $pageSize=10 ,$pageNum=1)
    {
        $arr = Array(
            "Action" => "DescribeDomainRecords",    // 业务类型标识，请勿修改
            "DomainName" => $domain,          // 要解析的域名
            'pageSize'=>$pageSize,
            'PageNumber'=>$pageNum,
        );
        if($type){
            $arr['Type'] = $type;
        }
        $this->param = array_merge($this->data, $arr);
        return $this->callInterface();
    }

    /**
     * @param string $domain 要解析的域名
     * @param string $type  记录类型A,txt...
     * @param int $pageNum
     * @param int $pageSize
     * @return bool|string
     */
    public function describeDomain( $pageSize=10 ,$pageNum=1)
    {
        $arr = Array(
            "Action" => "DescribeDomains",    // 业务类型标识，请勿修改
            'pageSize'=>$pageSize,
            'PageNumber'=>$pageNum,
        );
        $this->param = array_merge($this->data, $arr);
        return $this->callInterface();
    }
}


//检测证书信息
function check($domain)
{

    $context = stream_context_create(array("ssl" => array("capture_peer_cert_chain" => true,"capture_peer_cert" => true)));
    try{
        $socket = stream_socket_client("ssl://$domain:443", $errno, $errstr, 3, STREAM_CLIENT_CONNECT, $context);
        if($socket===false && $errno==0){
            throw new Exception('socket 连接失败');
        }
    }catch (Exception $e){
        //echo $e->getMessage(), PHP_EOL;
        return;
    }


    $context = stream_context_get_params($socket);

    //使用openssl扩展解析证书，这里使用x509证书验证函数
    $cerInfo = openssl_x509_parse($context["options"]["ssl"]["peer_certificate"]);
    if (strpos($cerInfo['name'], $domain)) {
        echo $domain,"\t\t\t\t";
        echo "start:" . date("Y-m-d", $cerInfo['validFrom_time_t']) ,"\t\t";
        echo "end:" . date("Y-m-d", $cerInfo['validTo_time_t']), PHP_EOL;
    }
}
set_error_handler(function($errNo, $errStr){
   echo $errNo, '---',$errStr, PHP_EOL;
});
$obj = new AliyunDNS($accessKeyId, $accessKeySecret);
$res = $obj->describeDomain();
$domainList = $res['Domains']['Domain']??[];

foreach($domainList as $domain){
    var_dump($domain['DnsServers']['DnsServer']);
    continue;
    $recordList = $obj->describeRecords($domain['DomainName'],'A');

    $recordList = $recordList['DomainRecords']['Record']??[];
    if(empty($recordList)) {
        continue;
    }
    foreach($recordList as $record){
        $host = $record['RR']=='@' ? $domain['DomainName'] : $record['RR'].'.'.$domain['DomainName'];
        check($host);
    }
}