package com.duque.cypher.error;

public class EncryptionError extends RuntimeException {

    public EncryptionError(Throwable t) {
        super(t);
    }

}
