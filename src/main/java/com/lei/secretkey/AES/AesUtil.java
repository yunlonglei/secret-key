package com.lei.secretkey.AES;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * AES加解密方式
 *
 * @author leiyunlong
 * @version 1.0
 * @since 2021/7/5 9:49 上午
 */
public class AesUtil {
    /**
     * 偏移量
     */
    private final static String iv = "d22b0a851e014f7b";

    private final static Base64.Encoder encoder = Base64.getEncoder();
    private final static Base64.Decoder decoder = Base64.getDecoder();

    private static final String DEFAULT_CHARSET = "UTF-8";
    private static final String KEY_AES = "AES";

    /**
     * 加密
     *
     * @param data 需要加密的内容
     * @param key  加密密码
     * @return
     */
    public static String encrypt(String data, String key) throws InvalidAlgorithmParameterException, UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return doAES(data, key, iv.getBytes(), Cipher.ENCRYPT_MODE);
    }

    /**
     * 解密
     *
     * @param data 待解密内容
     * @param key  解密密钥
     * @return
     */
    public static String decrypt(String data, String key) throws InvalidAlgorithmParameterException, UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return doAES(data, key, iv.getBytes(), Cipher.DECRYPT_MODE);
    }

    public static String doAES(String data, String secretKey, byte[] iv, int mode) throws UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
            boolean encrypt = mode == Cipher.ENCRYPT_MODE;
            byte[] content;
            //true 加密内容 false 解密内容
            if (encrypt) {
                content = data.getBytes(DEFAULT_CHARSET);
            } else {
                content = decoder.decode(data);
            }

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec skeySpec = new SecretKeySpec(secretKey.getBytes(), KEY_AES);
            cipher.init(mode, skeySpec, new IvParameterSpec(iv));
            byte[] result = cipher.doFinal(content);
            if (encrypt) {
                return new String(encoder.encode(result));
            } else {
                return new String(result, DEFAULT_CHARSET);
            }
    }

    public static void main(String[] args) throws InvalidAlgorithmParameterException, UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
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
