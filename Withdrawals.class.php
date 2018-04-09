<?php 
//appid是微信公众账号或开放平台APP的唯一标识，在公众平台申请公众账号或者在开放平台申请APP账号后，微信会自动分配对应的appid，用于标识该应用。
$appid = 'wxe274c50e5793a571';
//微信支付商户号
$mch_id = '1237737002';
//微信支付的key
$mch_key = 'UeTyq9yodDcHL2XCagCKsu7Aa3hJzYBK';

//证书目录是crl
$zhengshuPath = 'D:/phpStudy/WWW/wenxin/crl/';

class zhifu {
	public $config = [
		//appid是微信公众账号或开放平台APP的唯一标识，在公众平台申请公众账号或者在开放平台申请APP账号后，微信会自动分配对应的appid，用于标识该应用。
		'appid' => 'wxe274c50e5793a571',
		//微信支付商户号
		'mch_id' => '1237737002',
		//微信支付的key
		'mch_key' => 'UeTyq9yodDcHL2XCagCKsu7Aa3hJzYBK',
		//证书目录是crl
		'zhengshuPath' => 'D:/phpStudy/WWW/WeChatWithdrawals/crl/'
	];
	

	public function __construct($config =[]){
		if(is_array($config)){
			$this->config = array_merge($this->config,$config);
		}
	}

	/**提现到余额
	*partner_trade_no 订单号
	*openid 提现到用户的opendi
	* check_name 是否强制校验名字真实性
	*re_user_name  姓名
	*amount  提现金额  
	*desc 备注
	*spbill_create_ip 该IP可传用户端或者服务端的IP。
	*/
	public function index($partner_trade_no, $openid, $check_name='NO_CHECK',$re_user_name,$amount,$desc,$spbill_create_ip){
		$appid = $this->config['appid'];
		$mch_key = $this->config['mch_key'];
		$mch_id = $this->config['mch_id'];
		$nonce_str = self::randString();
		$post = [
			'mch_appid' => $appid,
			'mchid' => $mch_id,
			'nonce_str' => $nonce_str,
			'partner_trade_no' => $partner_trade_no,
			'openid' => $openid,
			'check_name' => $check_name, // NO_CHECK  不校验姓名  FORCE_CHECK 强制校验姓名
			're_user_name' => $re_user_name,
			'amount' => $amount * 100,
			'desc' => $desc,
			'spbill_create_ip' => $spbill_create_ip
		];
		
		$post['sign'] = $this->sign($post);
		$post_xml = self::arr2xml($post);
		$url = 'https://api.mch.weixin.qq.com/mmpaymkttransfers/promotion/transfers';
		//发送到微信接口
		$xml = $this->sendWx($url,$post_xml);
		$result = $this->xml($xml);
		return $result;
	}
	/**
	*partner_trade_no 订单编号
	*enc_bank_no 银行卡好
	*enc_true_name 真实姓名
	*bank_code  银行码
	*amount  付款金额
	*desc   备注
	*/
	//提现到银行卡
	public function takeBankCard($partner_trade_no,$enc_bank_no,$enc_true_name,$bank_code,$amount,$desc =''){
		$mch_id = $this->config['mch_id'];
		$nonce_str = $this->randString();
		$enc_bank_no = $this->getpublickey($enc_bank_no);
		$enc_true_name = $this->getpublickey($enc_true_name);
		$post = [
			'mch_id' => $mch_id,
			'partner_trade_no' => $partner_trade_no,
			'nonce_str' => $nonce_str,
			'enc_bank_no' => $enc_bank_no,
			'enc_true_name' => $enc_true_name,
			'bank_code' => $bank_code,
			'amount' => $amount * 100,
			'desc' => $desc
		];
		$sign = $this->sign($post);
		$post['sign'] = $sign;
		$post_xml = $this->arr2xml($post);
		// echo $post_xml;die;
		$url = 'https://api.mch.weixin.qq.com/mmpaysptrans/pay_bank';
		$res_xml = $this->sendWx($url, $post_xml);
		$arr = $this->xml($res_xml);

		return $arr;

	}

	/**
	*查询提现到余额进程
	*partner_trade_no   订单号
	*/
	public function queryTobalance($partner_trade_no){
		$mch_id = $this->config['mch_id'];
		$appid = $this->config['appid'];

		$post = [
			'appid' => $appid,
			'mch_id' => $mch_id,
			'partner_trade_no' => $partner_trade_no,
			'nonce_str' => $this->randString()
		];
		$sign = $this->sign($post);
		$post['sign'] = $sign;
		$post_xml = $this->arr2xml($post);
		$url = 'https://api.mch.weixin.qq.com/mmpaymkttransfers/gettransferinfo';
		$res = $this->sendWx($url,$post_xml);
		return $res;

	}
	//查询提现到银行卡进程
	public function queryTobankNo($partner_trade_no){
		$mch_id = $this->config['mch_id'];
		$nonce_str = $this->randString();
		$post = [
			'mch_id' => $mch_id,
			'nonce_str' => $nonce_str,
			'partner_trade_no' => $partner_trade_no
		];
		$sign = $this->sign($post);
		$post['sign'] = $sign;
		$post_xml = $this->arr2xml($post);
		// echo "$post_xml";die;
		$url = 'https://api.mch.weixin.qq.com/mmpaysptrans/query_bank';
		$res = $this->sendWx($url,$post_xml);
		return $res;
	}
	//获取微信rsa公钥
	//需要安装OpenSSL
	public function getRSAFile(){
		$mch_id = $this->config['mch_id'];
		$nonce_str = $this->randString();
		$post = [
			'mch_id' => $mch_id,
			'nonce_str' => $nonce_str,
		];
		$sign = $this->sign($post);
		$post['sign'] = $sign;
		$post_xml = $this->arr2xml($post);
		$url = "https://fraud.mch.weixin.qq.com/risk/getpublickey";
		$res = $this->sendWx($url,$post_xml);
		$res = $this->xml($res);
		if($res['RETURN_CODE'] == 'SUCCESS' && $res['RESULT_CODE'] == 'SUCCESS'){

			if(file_put_contents($this->config['zhengshuPath'].'public.pem', $res['PUB_KEY'])){
				//PKCS#1 转 PKCS#8: 需要安装OpenSSL
				exec("openssl rsa -RSAPublicKey_in -in ".$this->config['zhengshuPath'].'public.pem'." -pubout",$arr);

				$str = '';
				foreach ($arr as $key => $value) {
					$str .= $value ."\n";
				}
				// var_dump($a);
				file_put_contents($this->config['zhengshuPath'].'public.pem', $str);
				return $this->config['zhengshuPath'].'public.pem';
			}else{
				die('生成微信rsa公钥失败！无法提现');
			}
		}else{
			die('获取微信rsa公钥失败！无法提现');
		}


	}
	//使用rsa公钥加密
	public function getpublickey($str){
		
		$file_path = $this->config['zhengshuPath'].'public.pem';
		//没有这个文件就获取文件
		if(!is_file($file_path)){
			$this->getRSAFile();
		}
		if(is_file($file_path)){
			$f= file_get_contents($file_path);
			$pu_key = openssl_pkey_get_public($f);//读取公钥内容
			if(!$pu_key ){
				die('读取公钥内容失败');
			}
			$encryptedBlock = '';
        	$encrypted = '';
			// 用标准的RSA加密库对敏感信息进行加密，选择RSA_PKCS1_OAEP_PADDING填充模式
	        openssl_public_encrypt($str,$encryptedBlock,$pu_key,OPENSSL_PKCS1_OAEP_PADDING);
	        // 得到进行rsa加密并转base64之后的密文
	        $str_base64  = base64_encode($encrypted.$encryptedBlock);
	        return $str_base64;
		}else{
			die('微信rsa公钥不存在');
		}
		
	}
	//请求微信接口
	public function sendWx($url,$data,$headers = []){
		//证书目录
		$zspath = $this->config['zhengshuPath'];
		$ch = curl_init();
		//是否有头信息
		if(!empty($headers)){
			curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
		}

		curl_setopt($ch,CURLOPT_URL,$url);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch,CURLOPT_TIMEOUT,60); //超时时间
        curl_setopt($ch,CURLOPT_SSLCERT,$zspath.'apiclient_cert.pem');
        curl_setopt($ch,CURLOPT_SSLKEY,$zspath.'apiclient_key.pem');

        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        $data = curl_exec($ch);

        if (!empty($data)){
            curl_close($ch);
            return $data;
        }
        else{
            $error = curl_errno($ch);
            echo "curl出错，错误码:$error"."<br>";
            echo "call faild, errorCode:$error\n";
            curl_close($ch);
            return false;
        }
	}

	//生成32位随机字符串
	static public function randString(){
		$str = "123456789qwertyuiopasdfghjklmnbvcxzQWERTYUIOPLKJHGFDSAZXCVBNM";
		$randString = '';
		for($i=0;$i<32;$i++){
			$k = rand(0,strlen($str)-1);
			$randString .= $str[$k];
		}
		return strtoupper($randString);
	}

	//生成微信规则的签名
	public function sign($data){
		ksort($data);
		$stringA = '';
		foreach ($data as $key => $value) {
			if(!empty($value)){
				if(empty($stringA)){
					$stringA .= $key.'='.$value;
				}else{
					$stringA .= '&'.$key.'='.$value;
				}
			}
		}
		$stringA = $stringA.'&key='.$this->config['mch_key'];

		return strtoupper(md5($stringA));
	}

	//数组转xml
	static public function arr2xml($data, $root = true){
		$str="";
		if($root)
			$str .= "<xml>"."\n";
		foreach($data as $key => $val){
			if(is_array($val)){
			  $child = self::arr2xml($val, false);
			  $str .= "<$key>$child</$key>"."\n";
			}else{
			  $str.= "<$key><![CDATA[$val]]></$key>"."\n";
			}
		}
		if($root)
			$str .= "</xml>";
		return $str;
	}

	//xml转换数组
	public function xml($xml){
        libxml_disable_entity_loader(true);
        $data= json_decode(json_encode(simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOCDATA)), true);
        $data=array_change_key_case($data,CASE_UPPER);
        return $data;
    }
}
header("Content-type:text/html;charset=utf-8");

$zhifu = new zhifu();

//$partner_trade_no,$enc_bank_no,$enc_true_name,$bank_code,$amount,$desc =''
// $a = $zhifu->takeBankCard('12121211221227','6217002020057184756','杨文斌',1003,0.01,'test');

// $a = $zhifu->queryTobankNo('12121211221227');
// $a= $zhifu->xml($a);
// var_dump($a['STATUS']);
//提现到余额115.159.29.184
$rs = $zhifu->index('121212112212278','o_nAl0e4kF15z6n2mOL3c_EGJHXA','NO_CHECK','张三',0.01,'test','115.159.29.184');
var_dump($rs);