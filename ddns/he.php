<?php

$conf = [
    'localIp'=>'',//����IP,Ĭ�Ͽ��Զ���ȡ���Զ���ȡʧ�ܵ�������ֶ�����
    'ipUrl' =>'https://myip.biturl.top/',//�Զ���ȡ����ip�Ľӿ�
    'recordUrl' =>'http://dns.series.ink/?a=query&dns=%s&domain=%s&type=%s',//����������¼��ѯ�ӿ�
    'dnsTpl' =>'https://%s:%s@dyn.dns.he.net/nic/update?hostname=%s&myip=%s',//������¼���½ӿ�
    'names'=>[
        ['name'=>'series.ink','key'=>'xxxxxxx','ns'=>'ns1.he.net'],
        ['name'=>'www.series.ink','key'=>'xxxxxxx','ns'=>'ns1.he.net'],
    ],
];

//��ȡ����ip
if (empty($conf['localIp'])) {
    $outIpUrl = $conf['ipUrl'];
    $localIp = file_get_contents($outIpUrl);
    $b = preg_match("/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/", $localIp);
    if ($b !==1) {
        echo '�Զ���ȡ��������IPʧ�ܣ����ֶ���ȡ';
        exit(1);
    }
} else {
    $localIp = $conf['localIp'];
}

//ѭ����鲢����dns��¼
foreach ($conf['names'] as $v) {
    $reqUrl = sprintf($conf['recordUrl'], $v['ns'], $v['name'], 'A');
    echo "������",$v['name'], "\t";
    $data = file_get_contents($reqUrl);
    $data = json_decode($data, true);
    if (empty($data) || !isset($data['data'][0]['ipv4'])) {
        echo "δ��ѯ��dns��¼", "\t";
    } else {
        $dnsIp = $data['data'][0]['ipv4'];
        if ($dnsIp == $localIp) {
            echo "ipδ����:".$dnsIp, PHP_EOL;
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
