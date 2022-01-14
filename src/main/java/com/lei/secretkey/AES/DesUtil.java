package com.lei.secretkey.AES;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.util.Base64;

/**
 * @author leiyunlong
 * @version 1.0
 * @since 2021/7/5 10:26 上午
 */
public class DesUtil {
    /**
     * 偏移变量，固定占8位字节
     */
    private final static String IV_PARAMETER = "12345678";
    /**
     * 密钥算法
     */
    private static final String ALGORITHM = "DES";
    /**
     * 加密/解密算法-工作模式-填充模式
     */
    private static final String CIPHER_ALGORITHM = "DES/CBC/PKCS5Padding";
    /**
     * 默认编码
     */
    private static final String CHARSET = "utf-8";

    /**
     * DES加密字符串
     *
     * @param key  加密密码，长度不能够小于8位
     * @param data 待加密字符串
     * @return 加密后内容
     */
    public static String encrypt(String data, String key) {
        if (key == null || key.length() < 8) {
            throw new RuntimeException("加密失败，key不能小于8位");
        }
        if (data == null) {
            return null;
        }
        try {
            // 格式化密钥
            DESKeySpec dks = new DESKeySpec(key.getBytes(CHARSET));
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
            Key secretKey = keyFactory.generateSecret(dks);

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            IvParameterSpec iv = new IvParameterSpec(IV_PARAMETER.getBytes(CHARSET));
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
            byte[] bytes = cipher.doFinal(data.getBytes(CHARSET));

            return new String(Base64.getEncoder().encode(bytes));

        } catch (Exception e) {
            e.printStackTrace();
            return data;
        }
    }

    /**
     * DES解密字符串
     *
     * @param key  解密密码，长度不能够小于8位
     * @param data 待解密字符串
     * @return 解密后内容
     */
    public static String decrypt(String data, String key) {
        if (key == null || key.length() < 8) {
            throw new RuntimeException("加密失败，key不能小于8位");
        }
        if (data == null) {
            return null;
        }
        try {
            // 格式化密钥
            DESKeySpec dks = new DESKeySpec(key.getBytes(CHARSET));
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
            Key secretKey = keyFactory.generateSecret(dks);

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            IvParameterSpec iv = new IvParameterSpec(IV_PARAMETER.getBytes(CHARSET));
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
            return new String(cipher.doFinal(Base64.getDecoder().decode(data.getBytes(CHARSET))), CHARSET);
        } catch (Exception e) {
            e.printStackTrace();
            return data;
        }
    }

    public static void main(String[] args) {
        // 原始数据
        String data = "123456";
        // 密钥
        String key = "CtSSIdC9wfhkwtK9";
        System.out.println("原数据：" + data);
        System.out.println("密钥：" + key);
        String encrypt = encrypt(data, key);
        System.out.println("加密后数据：" + encrypt);
        String decrypt = decrypt(encrypt, key);
        System.out.println("解密后数据：" + decrypt);
    }
}
