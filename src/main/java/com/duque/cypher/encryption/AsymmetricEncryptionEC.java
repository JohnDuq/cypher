package com.duque.cypher.encryption;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

@Slf4j
@NoArgsConstructor
public class AsymmetricEncryptionEC extends AsymmetricEncryption {

    private static final String SECP_256_R_1 = "secp256r1";
    private static final String INSTANCE = "EC";
    private static final String PROVIDER = "BC";
    private static final String TRANSFORMATION = "ECIES";

    public static KeyPair generateKeyPair() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(INSTANCE, PROVIDER);
        keyPairGenerator.initialize(ECNamedCurveTable.getParameterSpec(SECP_256_R_1));
        return keyPairGenerator.generateKeyPair();
    }

    public static String getPublicKeyAsString(KeyPair keyPair) {
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        return encode(publicKey.getEncoded());
    }

    public static String getPrivateKeyAsString(KeyPair keyPair) {
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        return encode(privateKey.getEncoded());
    }

    public static String encrypt(String publicKey, String valueToEncrypt) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, toPublicKey(INSTANCE, publicKey));
        return encode(cipher.doFinal(valueToEncrypt.getBytes()));
    }

    public static String decrypt(String privateKey, String encryptedValue) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, PROVIDER);
        cipher.init(Cipher.DECRYPT_MODE, toPrivateKey(INSTANCE, privateKey));
        return new String(cipher.doFinal(decode(encryptedValue)));
    }

    public static void main(String[] args) {
        try {
            KeyPair keyPair = AsymmetricEncryptionEC.generateKeyPair();

            String publicKey = AsymmetricEncryptionEC.getPublicKeyAsString(keyPair);
            String privateKey = AsymmetricEncryptionEC.getPrivateKeyAsString(keyPair);

            log.debug("Public key     : {}", publicKey);
            log.debug("Private key    : {}", privateKey);

            String plainText = "Hello, world!";
            log.debug("Plaintext      : {}", plainText);

            String encryptedText = AsymmetricEncryptionEC.encrypt(publicKey, plainText);
            log.debug("Encrypted text : {}", encryptedText);

            String decryptedText = AsymmetricEncryptionEC.decrypt(privateKey, encryptedText);
            log.debug("Decrypted text : {}", decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
