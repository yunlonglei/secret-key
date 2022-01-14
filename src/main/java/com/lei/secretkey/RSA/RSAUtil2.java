package com.lei.secretkey.RSA;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;



/**
 * 对密钥（公钥、私钥）对统一进行处理
 * @author leiyunlong
 * @version 1.0
 * @since 2021/7/6 5:29 下午
 */
public class RSAUtil2 {

    /**
     * 用于封装随机产生的公钥与私钥
     */
    private static final Map<Integer, String> KEY_MAP = new HashMap<>();

    public static String data = "12345";

    /**
     * 生成密钥对
     *
     * @throws NoSuchAlgorithmException 异常
     */
    private static void generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator;
        keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        // 获取公钥，并以base64格式打印出来
        PublicKey publicKey = keyPair.getPublic();
        String publicKeyStr = Base64.encodeBase64String(publicKey.getEncoded());
        // 获取私钥，并以base64格式打印出来
        PrivateKey privateKey = keyPair.getPrivate();
        String privateKeyStr = new String(Base64.encodeBase64String(privateKey.getEncoded()));
        // 将公钥和私钥保存到Map
        KEY_MAP.put(0, publicKeyStr);
        KEY_MAP.put(1, privateKeyStr);
    }

    /**
     * 将base64编码后的公钥字符串转成PublicKey实例
     *
     * @param publicKey
     * @return
     * @throws Exception
     */
    private static PublicKey getPublicKey(String publicKey) throws Exception {
        byte[] keyBytes = Base64.decodeBase64(publicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * 将base64编码后的私钥字符串转成PrivateKey实例
     *
     * @param privateKey
     * @return
     * @throws Exception
     */
    private static PrivateKey getPrivateKey(String privateKey) throws Exception {
        byte[] keyBytes = Base64.decodeBase64(privateKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * 公钥加密
     *
     * @param content
     * @return
     * @throws Exception
     */
    public static String encryptByPublicKey(String content) throws Exception {
        // 获取公钥
        PublicKey publicKey = getPublicKey(KEY_MAP.get(0));
        // 这个地方加密用什么方法，解密就要用什么方法"RSA/ECB/PKCS1Padding"
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = cipher.doFinal(content.getBytes());
        String cipherStr = Base64.encodeBase64String(cipherText);
        return cipherStr;
    }


    /**
     * 私钥解密
     *
     * @param content
     * @return
     * @throws Exception
     */
    public static String decryptByPrivateKey(String content) throws Exception {
        // 获取私钥
        PrivateKey privateKey = getPrivateKey(KEY_MAP.get(1));
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] cipherText = Base64.decodeBase64(content);
        byte[] decryptText = cipher.doFinal(cipherText);
        return new String(decryptText);
    }

    /**
     * 私钥加密
     *
     * @param content
     * @return
     * @throws Exception
     */
    public static String encryptByPrivateKey(String content) throws Exception {
        // 获取私钥
        PrivateKey privateKey = getPrivateKey(KEY_MAP.get(1));
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] cipherText = cipher.doFinal(content.getBytes());
        String cipherStr = Base64.encodeBase64String(cipherText);
        return cipherStr;
    }

    /**
     * 公钥解密
     * @param content
     * @return
     * @throws Exception
     */
    public static String decryptByPublicKey(String content) throws Exception {
        // 获取公钥
        PublicKey publicKey = getPublicKey(KEY_MAP.get(0));
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] cipherText = Base64.decodeBase64(content);
        byte[] decryptText = cipher.doFinal(cipherText);
        return new String(decryptText);
    }

    public static void main(String[] args) throws Exception {
        //生成公钥和私钥
        generateKeyPair();
        //加密字符串
        String data = "123456";
        System.out.println("原数据：" + data);
        System.out.println("随机生成的公钥为:" + KEY_MAP.get(0));
        System.out.println("随机生成的私钥为:" + KEY_MAP.get(1));
        System.out.println("======公钥加密、私钥解密======");
        String encryptByPublicKey = encryptByPublicKey(data);
        System.out.println("加密后的字符串为:" + encryptByPublicKey);
        String decryptByPrivateKey = decryptByPrivateKey(encryptByPublicKey);
        System.out.println("解密后的字符串为:" + decryptByPrivateKey);
        System.out.println("============");
        System.out.println("======私钥加密、公钥解密======");
        String encryptByPrivateKey = encryptByPrivateKey(data);
        System.out.println("加密后的字符串为:" + encryptByPrivateKey);
        String decryptByPublicKey = decryptByPublicKey(encryptByPrivateKey);
        System.out.println("解密后的字符串为:" + decryptByPublicKey);
    }
}
