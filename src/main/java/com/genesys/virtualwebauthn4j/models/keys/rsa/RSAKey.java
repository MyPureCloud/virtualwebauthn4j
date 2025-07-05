package com.genesys.virtualwebauthn4j.models.keys.rsa;


import com.genesys.virtualwebauthn4j.WebAuthnUtil;
import com.genesys.virtualwebauthn4j.models.keys.SigningKey;

import java.security.*;
import java.security.interfaces.RSAPublicKey;

public class RSAKey implements SigningKey {
    private final KeyPair keyPair;

    private static final int rsaSize = 2048;
    private static final int rsaType = 3;
    public static final int rsaSHA256Algo = -257;

    public RSAKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(rsaSize);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] KeyData() {
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        RSAKeyInfo rsaKeyInfo = new RSAKeyInfo(
                rsaType,
                rsaSHA256Algo,
                rsaPublicKey.getModulus().toByteArray(),
                WebAuthnUtil.bigEndianBytes(rsaPublicKey.getPublicExponent().intValue(), 3)
        );

        return WebAuthnUtil.marshalCbor(rsaKeyInfo);
    }

    @Override
    public byte[] Sign(byte[] data) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(keyPair.getPrivate());
            signature.update(data);
            return signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }
}
