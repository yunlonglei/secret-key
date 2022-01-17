package com.lei.secretkey.SM4;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;

/**
 * 国秘4 SM4 加密
 * ECB
 * @author leiyunlong
 * @version 1.0
 * @since 2021/7/5 10:01 上午
 */
public class SM4_ECB_Util {
    private final static String ENCODING = "UTF-8";
    private final static String ALGORITHM_NAME = "SM4";
    private final static String ALGORITHM_NAME_ECB_PADDING = "SM4/ECB/PKCS5Padding";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static Cipher getCipher(int mode, String key) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(ALGORITHM_NAME_ECB_PADDING, BouncyCastleProvider.PROVIDER_NAME);
        Key sm4Key = new SecretKeySpec(ByteUtils.fromHexString(key), ALGORITHM_NAME);
        cipher.init(mode, sm4Key);
        return cipher;
    }

    /**
     * 加密
     *
     * @param content 加密内容
     * @param key     私钥
     * @return
     * @throws Exception
     */
    public static String encrypt(String content, String key) throws Exception {
        return ByteUtils.toHexString(getCipher(Cipher.ENCRYPT_MODE, key).doFinal(content.getBytes(ENCODING)));
    }

    /**
     * 解密
     *
     * @param content 解密内容
     * @param key     私钥
     * @return
     * @throws Exception
     */
    public static String decrypt(String content, String key) throws Exception {
        return new String(getCipher(Cipher.DECRYPT_MODE, key).doFinal(ByteUtils.fromHexString(content)), ENCODING);
    }

    /**
     * 自动生成密钥
     *
     * @return
     * @explain
     */
    public static String generateKey(int keySize) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        kg.init(keySize, new SecureRandom());
        byte[] encoded = kg.generateKey().getEncoded();
        return new String(Hex.encodeHex(encoded, false));
    }

    public static void main(String[] args) throws Exception {
        // 原始数据
        String data = "123456";
        // 密钥
        String key = generateKey(128);
        System.out.println("原数据：" + data);
        System.out.println("密钥：" + key);
        String encrypt = encrypt(data, key);
        System.out.println("加密后数据：" + encrypt);
        String decrypt = decrypt(encrypt, key);
        System.out.println("解密后数据：" + decrypt);
    }
}
