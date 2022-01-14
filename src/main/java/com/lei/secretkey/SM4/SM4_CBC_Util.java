package com.lei.secretkey.SM4;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

/**
 * 国秘4 SM4 加密
 * ECB
 *
 * @author leiyunlong
 * @version 1.0
 * @since 2021/7/5 10:01 上午
 */
public class SM4_CBC_Util {
    private final static String ENCODING = "UTF-8";
    private final static String ALGORITHM_NAME = "SM4";
    private final static String ALGORITHM_NAME_CBC_PADDING = "SM4/CBC/PKCS5Padding";
    private final static String IV = "czRxFrUlRN3gfaDR";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 加解密抽象方法
     * @param algorithmName
     * @param mode
     * @param key
     * @return
     * @throws Exception
     */
    private static Cipher generateCbcCipher(String algorithmName, int mode, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithmName, BouncyCastleProvider.PROVIDER_NAME);
        Key sm4Key = new SecretKeySpec(key, ALGORITHM_NAME);
        byte[] iv = IV.getBytes(ENCODING);
        AlgorithmParameters ivParams = AlgorithmParameters.getInstance(ALGORITHM_NAME);
        ivParams.init(new IvParameterSpec(iv));
        cipher.init(mode, sm4Key, ivParams);
        return cipher;
    }


    /**
     * 自动生成密钥
     *
     * @return
     * @explain
     */
    public static byte[] generateKey(int keySize) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        kg.init(keySize, new SecureRandom());
        return kg.generateKey().getEncoded();
    }

    /**
     * 加密模式之CBC
     *
     * @param key  密钥
     * @param data 数据
     * @return 加密后的字符串
     * @throws Exception
     * @explain
     */
    public static String encrypt(String data, String key) throws Exception {
        // 16进制字符串-->byte[]
        byte[] keyData = ByteUtils.fromHexString(key);
        // String-->byte[]
        byte[] srcData = data.getBytes(ENCODING);
        Cipher cipher = generateCbcCipher(ALGORITHM_NAME_CBC_PADDING, Cipher.ENCRYPT_MODE, keyData);
        byte[] cipherArray = cipher.doFinal(srcData);
        return ByteUtils.toHexString(cipherArray);
    }

    /**
     * @param key  密钥
     * @param data 数据
     * @return 解密字符串
     * @throws Exception
     */
    public static String decrypt(String data, String key) throws Exception {
        // 16进制字符串-->byte[]
        byte[] keyData = ByteUtils.fromHexString(key);
        // String-->byte[]
        byte[] srcData = ByteUtils.fromHexString(data);
        Cipher cipher = generateCbcCipher(ALGORITHM_NAME_CBC_PADDING, Cipher.DECRYPT_MODE, keyData);
        byte[] cipherArray = cipher.doFinal(srcData);
        return new String(cipherArray, ENCODING);
    }

    public static void main(String[] args) throws Exception {
        // 原始数据
        String data = "123456";
        // 密钥
        String key = new String(Hex.encodeHex(generateKey(128), false));
//        String key = "525133D1229783B2";
        System.out.println("原数据：" + data);
        System.out.println("密钥：" + key);
        String encrypt = encrypt(data, key);
        System.out.println("加密后数据：" + encrypt);
        String decrypt = decrypt(encrypt, key);
        System.out.println("解密后数据：" + decrypt);
    }
}
