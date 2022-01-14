package com.lei.secretkey.SM2;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.util.Base64Utils;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;

/**
 * @author leiyunlong
 * @version 1.0
 * @since 2021/7/7 8:54 上午
 */
public class SM2Util {

    private final static Digest DIGEST = new SM3Digest();

    /**
     * 私钥转换为 {@link ECPrivateKeyParameters}
     *
     * @param key key
     * @return
     * @throws InvalidKeyException
     */
    public static ECPrivateKeyParameters privateKeyToParams(String algorithm, byte[] key) throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException {
        PrivateKey privateKey = generatePrivateKey(algorithm, key);
        return (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(privateKey);
    }

    /**
     * 生成私钥
     *
     * @param algorithm 算法
     * @param key       key
     * @return
     */
    public static PrivateKey generatePrivateKey(String algorithm, byte[] key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec keySpec = new PKCS8EncodedKeySpec(key);
        algorithm = getAlgorithmAfterWith(algorithm);
        return getKeyFactory(algorithm).generatePrivate(keySpec);
    }

    /**
     * 公钥转换为 {@link ECPublicKeyParameters}
     *
     * @param key key
     * @return
     * @throws InvalidKeyException
     */
    public static ECPublicKeyParameters publicKeyToParams(String algorithm, byte[] key) throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException {
        PublicKey publicKey = generatePublicKey(algorithm, key);
        return (ECPublicKeyParameters) ECUtil.generatePublicKeyParameter(publicKey);
    }

    /**
     * 生成公钥
     *
     * @param algorithm 算法
     * @param key       key
     * @return
     */
    public static PublicKey generatePublicKey(String algorithm, byte[] key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec keySpec = new X509EncodedKeySpec(key);
        algorithm = getAlgorithmAfterWith(algorithm);
        return getKeyFactory(algorithm).generatePublic(keySpec);
    }

    /**
     * 获取用于密钥生成的算法<br>
     * 获取XXXwithXXX算法的后半部分算法，如果为ECDSA或SM2，返回算法为EC
     *
     * @param algorithm XXXwithXXX算法
     * @return 算法
     */
    private static String getAlgorithmAfterWith(String algorithm) {
        int indexOfWith = StringUtils.lastIndexOfIgnoreCase(algorithm, "with");
        if (indexOfWith > 0) {
            algorithm = StringUtils.substring(algorithm, indexOfWith + "with".length());
        }
        if ("ECDSA".equalsIgnoreCase(algorithm) || "SM2".equalsIgnoreCase(algorithm)) {
            algorithm = "EC";
        }
        return algorithm;
    }

    /**
     * 获取{@link KeyFactory}
     *
     * @param algorithm 非对称加密算法
     * @return {@link KeyFactory}
     */
    private static KeyFactory getKeyFactory(String algorithm) throws NoSuchAlgorithmException {
        final Provider provider = new BouncyCastleProvider();
        return KeyFactory.getInstance(algorithm, provider);
    }

    /**
     * SM2算法生成密钥对
     *
     * @return 密钥对信息
     */
    public static KeyPair generateSm2KeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        final ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");
        // 获取一个椭圆曲线类型的密钥对生成器
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        SecureRandom random = new SecureRandom();
        // 使用SM2的算法区域初始化密钥生成器
        kpg.initialize(sm2Spec, random);
        // 获取密钥对
        return kpg.generateKeyPair();
    }

    /**
     * 加密
     *
     * @param data      数据
     * @param publicKey 公钥
     * @return 加密之后的数据
     */
    public static byte[] encrypt(byte[] data, byte[] publicKey) throws Exception {
        CipherParameters pubKeyParameters = new ParametersWithRandom(publicKeyToParams("SM2", publicKey));
        SM2Engine engine = new SM2Engine(DIGEST);
        engine.init(true, pubKeyParameters);
        return engine.processBlock(data, 0, data.length);
    }

    /**
     * 解密
     *
     * @param data       数据
     * @param privateKey 私钥
     * @return 解密之后的数据
     */
    public static byte[] decrypt(byte[] data, byte[] privateKey) throws Exception {
        CipherParameters privateKeyParameters = privateKeyToParams("SM2", privateKey);
        SM2Engine engine = new SM2Engine(DIGEST);
        engine.init(false, privateKeyParameters);
        return engine.processBlock(data, 0, data.length);
    }

    /**
     * 签名
     *
     * @param data 数据
     * @return 签名
     */
    public static byte[] sign(byte[] data, byte[] privateKey) throws Exception {
        SM2Signer signer = new SM2Signer();
        CipherParameters param = new ParametersWithRandom(privateKeyToParams("SM2", privateKey));
        signer.init(true, param);
        signer.update(data, 0, data.length);
        return signer.generateSignature();
    }

    /**
     * 用公钥检验数字签名的合法性
     *
     * @param data      数据
     * @param sign      签名
     * @param publicKey 公钥
     * @return 是否验证通过
     */
    public static boolean verify(byte[] data, byte[] sign, byte[] publicKey) throws Exception {
        SM2Signer signer = new SM2Signer();
        CipherParameters param = publicKeyToParams("SM2", publicKey);
        signer.init(false, param);
        signer.update(data, 0, data.length);
        return signer.verifySignature(sign);
    }

    public static void main(String[] args) throws Exception {
        KeyPair keyPair = generateSm2KeyPair();
        // 明文
        String plaintext = "123456";
        System.out.println("原数据：" + plaintext);
        String publicKey = Base64Utils.encodeToString(keyPair.getPublic().getEncoded());
        String privateKey = Base64Utils.encodeToString(keyPair.getPrivate().getEncoded());
        System.out.println("随机生成的公钥为:" + publicKey);
        System.out.println("随机生成的私钥为:" + privateKey);
        // 公钥加密
        byte[] ciphertext = Base64Utils.encode(encrypt(plaintext.getBytes(StandardCharsets.UTF_8), Base64Utils.decodeFromString(publicKey)));
        System.out.println("加密后数据: " + new String(ciphertext));
        // 签名
        byte[] signature = Base64Utils.encode(sign(plaintext.getBytes(StandardCharsets.UTF_8), Base64Utils.decodeFromString(privateKey)));
        System.out.println("签名结果: " + new String(signature));
        // 私钥解密
        plaintext = new String(decrypt(Base64Utils.decode(ciphertext), Base64Utils.decodeFromString(privateKey)), StandardCharsets.UTF_8);
        System.out.println("解密后数据: " + plaintext);
        // 验签
        boolean result = verify(plaintext.getBytes(StandardCharsets.UTF_8), Base64Utils.decode(signature), keyPair.getPublic().getEncoded());
        System.out.println("验签结果: " + result);
    }
}
