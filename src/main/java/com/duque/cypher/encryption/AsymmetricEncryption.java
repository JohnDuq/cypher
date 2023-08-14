package com.duque.cypher.encryption;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class AsymmetricEncryption {

    static byte[] decode(String value) {
        return Base64.getDecoder().decode(value);
    }

    static String encode(byte[] value) {
        return Base64.getEncoder().encodeToString(value);
    }

    static PublicKey toPublicKey(String instance, String publicKey) throws Exception {
        return KeyFactory.getInstance(instance).generatePublic(new X509EncodedKeySpec(decode(publicKey)));
    }

    static PrivateKey toPrivateKey(String instance, String privateKey) throws Exception {
        return KeyFactory.getInstance(instance).generatePrivate(new PKCS8EncodedKeySpec(decode(privateKey)));
    }

}
