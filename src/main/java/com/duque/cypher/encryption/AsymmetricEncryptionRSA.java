package com.duque.cypher.encryption;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

@Slf4j
@NoArgsConstructor
public class AsymmetricEncryptionRSA extends AsymmetricEncryption {

    private static final String INSTANCE = "RSA";

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(INSTANCE);
        keyGen.initialize(2048); // 512, 1024, 2048
        return keyGen.generateKeyPair();
    }

    public static String getPublicKeyAsString(KeyPair keyPair) {
        PublicKey publicKey = keyPair.getPublic();
        return encode(publicKey.getEncoded());
    }

    public static String getPrivateKeyAsString(KeyPair keyPair) {
        PrivateKey privateKey = keyPair.getPrivate();
        return encode(privateKey.getEncoded());
    }

    public static String encrypt(String publicKey, String valueToEncrypt) throws Exception {
        Cipher cipher = Cipher.getInstance(INSTANCE);
        cipher.init(Cipher.ENCRYPT_MODE, toPublicKey(INSTANCE, publicKey));
        return encode(cipher.doFinal(valueToEncrypt.getBytes()));
    }

    public static String decrypt(String privateKey, String encryptedValue) throws Exception {
        Cipher cipher = Cipher.getInstance(INSTANCE);
        cipher.init(Cipher.DECRYPT_MODE, toPrivateKey(INSTANCE, privateKey));
        return new String(cipher.doFinal(decode(encryptedValue)));
    }

    public static void main(String[] args) {
        try {
            KeyPair keyPair = AsymmetricEncryptionRSA.generateKeyPair();

            String publicKey = AsymmetricEncryptionRSA.getPublicKeyAsString(keyPair);
            String privateKey = AsymmetricEncryptionRSA.getPrivateKeyAsString(keyPair);

            log.debug("Public key     : {}", publicKey);
            log.debug("Private key    : {}", privateKey);

            String plainText = "Hello, world!";
            log.debug("Plaintext      : {}", plainText);

            String encryptedText = AsymmetricEncryptionRSA.encrypt(publicKey, plainText);
            log.debug("Encrypted text : {}", encryptedText);

            String decryptedText = AsymmetricEncryptionRSA.decrypt(privateKey, encryptedText);
            log.debug("Decrypted text : {}", decryptedText);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
