<?php
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
    public $url;

    public function __construct( $url, $KeyId, $KeySecret) {
        $this->url = $url;
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
        $this->data['Signature'] = $this->computeSignature($this->data, $this->accessKeySecret);
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $this->url . http_build_query($this->data));
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        $res = curl_exec($ch);
        return $res;
    }

    public function addRecord()
    {

    }

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
        $this->data = array_merge($this->data, $arr);
        return $this->callInterface();

    }

    public function describeRecords()
    {
        $arr = Array(
            "Action" => "DescribeDomainRecords",    // 业务类型标识，请勿修改
            "DomainName" => "vagrant.cn",          // 要解析的域名
            "RecordID" => "",                       // 记录ID，留空，请勿修改
            "Value" => "",                          // 记录值，留空，请勿修改
            "RR" => "ddns.ddns",                         // 解析主机名，改为你需要的
            "Type" => "A",                          // 记录类型，请勿修改
            "TTL" => 600                            // TTL 生存时间，默认 600
        );
        $this->data = array_merge($this->data, $arr);
        return $this->callInterface();
    }
}

/*
 *
 *    Config 配置
 *
 */

$url = "http://alidns.aliyuncs.com/?";
$api = "http://2017.ip138.com/ic.asp";      // 获取本机 IP 地址的 API

$accessKeyId = "6ltpchfckx9h8htgayp1txda";
$accessKeySecret = "GbJioobYI2qRmPex+WYOvpPgS5Q=";

$arr = Array(
    "Action" => "DescribeDomainRecords",    // 业务类型标识，请勿修改
    "DomainName" => "vagrant.cn",          // 要解析的域名
    "RecordID" => "",                       // 记录ID，留空，请勿修改
    "Value" => "",                          // 记录值，留空，请勿修改
    "RR" => "ddns.ddns",                         // 解析主机名，改为你需要的
    "Type" => "A",                          // 记录类型，请勿修改
    "TTL" => 600                            // TTL 生存时间，默认 600
);

/**
 * 获取本机外网IP
 * @return bool|false|string
 */
function localOutIp()
{
    $outIpApi='https://myip.biturl.top/';
    $localIp = file_get_contents($outIpApi);
    $b = preg_match("/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/", $localIp);
    if ($b !==1) {
        return false;
    }
    return $localIp;
}

/*
 *
 *    Request & Update 请求与域名解析更新
 *
 */

$NewIP = localOutIp();
$obj = new AliyunDNS($url, $accessKeyId, $accessKeySecret);
$recordList = json_decode($obj->callInterface(), true);
if(!$recordList) {
    echo "Failed get record list!";
    exit;
}
if(isset($recordList["DomainRecords"]["Record"])) {
    foreach($recordList["DomainRecords"]["Record"] as $id => $record) {
        if($record["RR"] == $arr["RR"] && $record["Type"] == "A") {
            $arr["RecordId"] = $record["RecordId"];
            $arr["Action"] = "UpdateDomainRecord";

            $arr["Value"] = $NewIP;

            if($arr["RecordId"] !== "" && $arr["Value"] !== "") {
                $obj = new AliyunDNS($arr, $url, $accessKeyId, $accessKeySecret);
                $result = json_decode($obj->callInterface(), true);

                if(isset($result["RecordId"]) && $result["RecordId"] == $record["RecordId"]) {
                    echo "Successful update domain record.";
                    exit;
                } else {
                    if(isset($result["Message"])) {
                        echo $result["Message"];
                    } else {
                        print_r($result);
                    }
                }
            } else {
                echo "Failed to get the ip address.";
                exit;
            }
        }
    }
} else {
    echo "Empty record list.";
    exit;
}