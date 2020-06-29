<?php
//你的密钥
$accessKeyId = "";
$accessKeySecret = "";
//要解析的域名记录
$records = [
    'vagrant.cn'=>['test','test.test','txt']
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
            'SignatureNonce'=> uniqid(),
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
        $this->param['Signature'] = $this->computeSignature($this->param, $this->accessKeySecret);
        return file_get_contents($this->url . http_build_query($this->param));
    }

    /**
     * @param $RR
     * @param $value
     * @param $domain
     * @param string $type
     * @param int $ttl
     * @return bool|string
     */
    public function addRecord($RR, $value, $domain, $type='A', $ttl=600)
    {
        $arr = Array(
            "Action" => "AddDomainRecord",    // 业务类型标识，请勿修改
            "DomainName" => $domain,          // 要解析的域名
            "Value" => $value,                          // 记录值，留空，请勿修改
            "RR" => $RR,                         // 解析主机名，改为你需要的
            "Type" => $type,                          // 记录类型，请勿修改
            "TTL" => $ttl                            // TTL 生存时间，默认 600
        );
        $this->param = array_merge($this->data, $arr);
        return $this->callInterface();
    }

    /**
     * @param $recordId
     * @param $RR
     * @param $value
     * @param $domain
     * @param string $type
     * @param int $ttl
     * @return bool|string
     */
    public function updateRecord($recordId, $RR, $value, $domain, $type='A',$ttl=600)
    {
        $arr = Array(
            "Action" => "UpdateDomainRecord",    // 业务类型标识，请勿修改
            "DomainName" => $domain,          // 要解析的域名
            "RecordID" => $recordId,                       // 记录ID，留空，请勿修改
            "Value" => $value,                          // 记录值，留空，请勿修改
            "RR" => $RR,                         // 解析主机名，改为你需要的
            "Type" => $type,                          // 记录类型，请勿修改
            "TTL" => $ttl                            // TTL 生存时间，默认 600
        );
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
    public function describeRecords($domain, $type='', $pageSize=10 ,$pageNum=1)
    {
        $arr = Array(
            "Action" => "DescribeDomainRecords",    // 业务类型标识，请勿修改
            "DomainName" => $domain,          // 要解析的域名
            'pageSize'=>$pageSize,
            'PageNumber'=>$pageNum,
        );
        if($type){
            $arr['type'] = $type;
        }
        $this->param = array_merge($this->data, $arr);
        return $this->callInterface();
    }
    /**
     * 获取本机外网IP
     * @return bool|false|string
     */
    public static function localOutIp()
    {
        $outIpApi='https://myip.biturl.top/';
        $localIp = file_get_contents($outIpApi);
        $b = preg_match("/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/", $localIp);
        if ($b !==1) {
            return false;
        }
        return $localIp;
    }
}


$newIP = AliyunDNS::localOutIp();
$obj = new AliyunDNS($accessKeyId, $accessKeySecret);
foreach($records as $domain=>$subList){
    $recordList = json_decode($obj->describeRecords($domain,'A'), true);
    $recordList = $recordList['DomainRecords']['Record']??[];
    if($recordList) {
        $recordList = array_combine(array_column($recordList,'RR'), $recordList);
    }
    foreach($subList as $sub){
        if(isset($recordList[$sub])){
            echo json_encode($recordList[$sub]),PHP_EOL,$newIP,PHP_EOL;
            if($recordList[$sub]['Value']==$newIP){
                echo "record already exist",PHP_EOL;
                continue;
            }
            $result = $obj->updateRecord($recordList[$subList]['RecordId'],$sub, $newIP,$domain);
            echo "update",PHP_EOL;
        }else{
            $result = $obj->addRecord($sub, $newIP, $domain);
            echo "add", PHP_EOL;
        }
        echo $result, PHP_EOL;
    }
}