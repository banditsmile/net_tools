<?php

$conf = [
    'localIp'=>'',//本地IP,默认空自动获取，自动获取失败的情况下手动设置
    'ipUrl' =>'https://myip.biturl.top/',//自动获取本地ip的接口
    'recordUrl' =>'http://dns.series.ink/?a=query&dns=%s&domain=%s&type=%s',//域名解析记录查询接口
    'dnsTpl' =>'https://%s:%s@dyn.dns.he.net/nic/update?hostname=%s&myip=%s',//域名记录更新接口
    'names'=>[
        ['name'=>'series.ink','key'=>'xxxxxxx','ns'=>'ns1.he.net'],
        ['name'=>'www.series.ink','key'=>'xxxxxxx','ns'=>'ns1.he.net'],
    ],
];

//获取本地ip
if (empty($conf['localIp'])) {
    $outIpUrl = $conf['ipUrl'];
    $localIp = file_get_contents($outIpUrl);
    $b = preg_match("/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/", $localIp);
    if ($b !==1) {
        echo '自动获取本地外网IP失败，请手动获取';
        exit(1);
    }
} else {
    $localIp = $conf['localIp'];
}

//循环检查并更新dns记录
foreach ($conf['names'] as $v) {
    $reqUrl = sprintf($conf['recordUrl'], $v['ns'], $v['name'], 'A');
    echo "域名：",$v['name'], "\t";
    $data = file_get_contents($reqUrl);
    $data = json_decode($data, true);
    if (empty($data) || !isset($data['data'][0]['ipv4'])) {
        echo "未查询到dns记录", "\t";
    } else {
        $dnsIp = $data['data'][0]['ipv4'];
        if ($dnsIp == $localIp) {
            echo "ip未更新:".$dnsIp, PHP_EOL;
            continue;
        }
    }

    $url = sprintf($conf['dnsTpl'], $v['name'], $v['key'], $v['name'], $localIp);
    echo $url,PHP_EOL;
    $ret=get($url);
    echo $ret,PHP_EOL;
}
exit(0);

function get($url, array $get = NULL, array $options = array())
{
    $url = $url. (strpos($url,  '?') === false ? '?' : ''). http_build_query($get);
    $defaults = array(
        CURLOPT_URL => $url,
        CURLOPT_HEADER => 0,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 4
    );

    $ch = curl_init();
    curl_setopt_array($ch, ($options + $defaults));
    if (!$result = curl_exec($ch)) {
        trigger_error(curl_error($ch));
    }
    curl_close($ch);
    return $result;
}
