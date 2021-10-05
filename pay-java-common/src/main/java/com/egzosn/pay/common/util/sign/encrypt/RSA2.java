
package com.egzosn.pay.common.util.sign.encrypt;

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

@Slf4j
public class RSA2 {

	private static final String SIGN_SHA256RSA_ALGORITHMS = "SHA256WithRSA";

	public static String sign(String content, String privateKey, String characterEncoding) {

		return RSA.sign(content, privateKey, SIGN_SHA256RSA_ALGORITHMS, characterEncoding);
	}



	/**
	 * RSA签名
	 * @param content 待签名数据
	 * @param privateKey 私钥
	 * @param characterEncoding 编码格式
	 * @return 签名值
	 */
	public static String sign(String content, PrivateKey privateKey ,String characterEncoding){
		return RSA.sign(content, privateKey, SIGN_SHA256RSA_ALGORITHMS, characterEncoding);
	}

	/**
	* RSA验签名检查
	* @param content 待签名数据
	* @param sign 签名值
	* @param  publicKey 公钥
	* @param characterEncoding 编码格式
	* @return 布尔值
	*/
	public static boolean verify(String content, String sign, String publicKey, String characterEncoding){

		log.info("-----------------------------alipay verify-----------------------------");
		log.info("content：{}" , content);
		log.info("sign：{}" ,  sign);
		log.info("publicKey：{}" ,  publicKey);
		log.info("characterEncoding：{}" ,  characterEncoding);

		boolean flag =	RSA.verify(content, sign, publicKey, SIGN_SHA256RSA_ALGORITHMS, characterEncoding );
		log.info("verify flag：{}" ,  flag);

		return flag;
	}



	/**
	 * RSA验签名检查
	 * @param content 待签名数据
	 * @param sign 签名值
	 * @param  publicKey 公钥
	 * @param characterEncoding 编码格式
	 * @return 布尔值
	 */
	public static boolean verify(String content, String sign, PublicKey publicKey, String characterEncoding){
		return RSA.verify(content, sign, publicKey, SIGN_SHA256RSA_ALGORITHMS, characterEncoding);
	}

	/**
	* 解密
	* @param content 密文
	* @param privateKey 商户私钥
	* @param characterEncoding 编码格式
	* @return 解密后的字符串
	 * @throws GeneralSecurityException 解密异常
	 * @throws IOException 解密异常
	*/
	public static String decrypt(String content, String privateKey, String characterEncoding) throws GeneralSecurityException, IOException {
        return RSA.decrypt(content, privateKey, characterEncoding);
    }


	/**
	* 得到私钥
	* @param key 密钥字符串（经过base64编码）
	* @throws GeneralSecurityException 加密异常
	 * @return 私钥
	*/
	public static PrivateKey getPrivateKey(String key) throws GeneralSecurityException {
		return RSA.getPrivateKey(key);
	}

	/**
	 *
	 * @param content 加密文本
	 * @param publicKey 公钥
	 * @param cipherAlgorithm 算法
	 * @param characterEncoding 编码类型
	 * @return 加密后文本
	 * @throws GeneralSecurityException 加密异常
	 * @throws IOException IOException
	 */
	public static String encrypt(String content, String publicKey, String cipherAlgorithm, String characterEncoding ) throws GeneralSecurityException, IOException {
		return Base64.encode(RSA.encrypt(content.getBytes(characterEncoding), RSA.getPublicKey(publicKey), 2048, 11, cipherAlgorithm));
	}

	public static void main(String args[]){
		String content = "app_id=2021002178670083&auth_app_id=2021002178670083&buyer_id=2088012411581559&buyer_logon_id=159****9796&buyer_pay_amount=1.00&charset=UTF-8&fund_bill_list=[{\"amount\":\"1.00\",\"fundChannel\":\"ALIPAYACCOUNT\"}]&gmt_create=2021-10-04 17:50:57&gmt_payment=2021-10-04 17:50:58&invoice_amount=1.00&notify_id=2021100400222175058081551447853667&notify_time=2021-10-04 17:50:58&notify_type=trade_status_sync&out_trade_no=ddefc9195b33483c8758bf44c9958939&point_amount=0.00&receipt_amount=1.00&seller_email=liukefu2050@sina.com&seller_id=2088241507754331&subject=商品&total_amount=1.00&trade_no=2021100422001481551441846604&trade_status=TRADE_SUCCESS&version=1.0";
		String sign = "hUE2/AXChxe9lxSIaem1syVwVl151O/PM9g6N8y20BdDe6kzQLQas1ggDbQem3D5ghC0JgpJvlvDHbZYTFOwUHteuEHLH8eFDfOFYWkeuMqomVVoTp/hjLnGHHZ32OCibhV0M45/7K09r19yKgFdEs5ubT7sDG3\n" +
				"eAJFT83uFV7Fh79cUfdvFNC9izyBy4ViwHVwUB9Mj7TiTsNdacUUVVvTqu3/2//w3OcuHwA6UGSeaU4VoK9Z5i0VOjV/T+zzQe1iXjzGJlJJp8njoqemGpB1aba7MB6v/xmDyvtJlNRoFp6NgVOsR6fQmi/BCgM6CFYJve62TD1kK45eUHXMRZw==";
		String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAidWV53H8EZpV74S1djTI5Wsxx1kRHNvScYn9dt2s0QpEShE7TzbcGrpf5Xju7Kxqf6+okNdIYiAHTx15+IXfvDGldGl8WbpSo13mDi/+N0GouOdNws6QyB3J3rdJga0nuPOJsECt/6ATM6bHmk4IvMShScOP1zYf7LGt3FWHsqX3gUYIz25i+WRwWUTDJuHp2R3gh/drJd/dbv+1eYH02g4Pqke1SkIOIn6sT1cXA6H7OEmznEuUFards+eCP1BUu5QTdldtSgdC/kFVkJd5Jv6zopav4Cg9E5/ywcK1gQJeAP/nQj5k4uGBpqt7/M1VHaw1298/QWYOOHrP/WBO+QIDAQAB";
		String characterEncoding = "UTF-8";
	    boolean flag =	RSA2.verify(content,sign,publicKey,characterEncoding);
	    System.out.println(flag);
	}
}
