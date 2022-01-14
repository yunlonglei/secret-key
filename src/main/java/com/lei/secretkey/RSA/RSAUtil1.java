package com.lei.secretkey.RSA;

import org.apache.commons.codec.binary.Base64;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * RSA加密
 * 在私钥加密、公钥解密码才对密钥进行处理
 * @author leiyunlong
 * @version 1.0
 * @since 2021/7/5 10:18 上午
 */
public class RSAUtil1 {
    /**
     * 用于封装随机产生的公钥与私钥
     */
    private static final Map<Integer, String> KEY_MAP = new HashMap<Integer, String>();

    /**
     * 随机生成密钥对
     *
     * @throws NoSuchAlgorithmException
     */
    public static void genKeyPair() throws NoSuchAlgorithmException {
        // KeyPairGenerator类用于生成公钥和私钥对，基于RSA算法生成对象
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        // 初始化密钥对生成器，密钥大小为96-1024位
        keyPairGen.initialize(1024, new SecureRandom());
        // 生成一个密钥对，保存在keyPair中
        KeyPair keyPair = keyPairGen.generateKeyPair();
        // 得到私钥
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        // 得到公钥
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        String publicKeyString = new String(Base64.encodeBase64(publicKey.getEncoded()));
        // 得到私钥字符串
        String privateKeyString = new String(Base64.encodeBase64((privateKey.getEncoded())));
        // 将公钥和私钥保存到Map
        KEY_MAP.put(0, publicKeyString);
        KEY_MAP.put(1, privateKeyString);
    }

    /**
     * RSA公钥加密
     *
     * @param str       加密字符串
     * @param publicKey 公钥
     * @return 密文
     * @throws Exception 加密过程中的异常信息
     */
    public static String encrypt(String str, String publicKey) throws Exception {
        //base64编码的公钥
        byte[] decoded = Base64.decodeBase64(publicKey);
        RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
        //RSA加密
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        return Base64.encodeBase64String(cipher.doFinal(str.getBytes("UTF-8")));
    }

    /**
     * RSA私钥解密
     *
     * @param str        加密字符串
     * @param privateKey 私钥
     * @return 明文
     * @throws Exception 解密过程中的异常信息
     */
    public static String decrypt(String str, String privateKey) throws Exception {
        //64位解码加密后的字符串
        byte[] inputByte = Base64.decodeBase64(str.getBytes(StandardCharsets.UTF_8));
        //base64编码的私钥
        byte[] decoded = Base64.decodeBase64(privateKey);
        RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
        //RSA解密
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        return new String(cipher.doFinal(inputByte));
    }

    /**
     * 私钥加密
     *
     * @param str           加密字符串
     * @param privateKeyStr 私钥
     * @return 加密密文
     * @throws Exception 解密过程中的异常信息
     */
    public static String encryptByPrivateKey(String str, String privateKeyStr) throws Exception {
        // 获取私钥 PKCS8EncodedKeySpec 用这样的私钥格式
        byte[] keyBytes = new BASE64Decoder().decodeBuffer(privateKeyStr);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        // 获取私钥
//        PrivateKey privateKey = getPrivateKey(KEY_MAP.get(1));
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] cipherText = cipher.doFinal(str.getBytes());
        return new BASE64Encoder().encode(cipherText);
    }

    /**
     * 公钥解密
     *
     * @param str           加密字符串
     * @param publicKeyStr 私钥
     * @return 加密密文
     * @throws Exception 解密过程中的异常信息
     */
    public static String decryptByPublicKey(String str, String publicKeyStr) throws Exception {
        // 获取公钥 PKCS8EncodedKeySpec 用这样的公钥格式
        byte[] keyBytes = new BASE64Decoder().decodeBuffer(publicKeyStr);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        // 获取公钥
//        PublicKey publicKey = getPublicKey(KEY_MAP.get(0));
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] cipherText = new BASE64Decoder().decodeBuffer(str);
        byte[] decryptText = cipher.doFinal(cipherText);
        return new String(decryptText);
    }

    public static void main(String[] args) throws Exception {
        //生成公钥和私钥
        genKeyPair();
        //加密字符串
        String data = "123456";
        System.out.println("原数据：" + data);
        System.out.println("随机生成的公钥为:" + KEY_MAP.get(0));
        System.out.println("随机生成的私钥为:" + KEY_MAP.get(1));

        System.out.println("======公钥加密、私钥解密======");
        String encrypt = encrypt(data, KEY_MAP.get(0));
        System.out.println("加密后的字符串为:" + encrypt);
        String decrypt = decrypt(encrypt, KEY_MAP.get(1));
        System.out.println("解密后的字符串为:" + decrypt);

        System.out.println("======私钥加密、公钥解密======");
        String encryptByPrivateKey = encryptByPrivateKey(data, KEY_MAP.get(1));
        System.out.println("加密后的字符串为:" + encryptByPrivateKey);
        String decryptByPublicKey = decryptByPublicKey(encryptByPrivateKey, KEY_MAP.get(0));
        System.out.println("解密后的字符串为:" + decryptByPublicKey);
    }
}
