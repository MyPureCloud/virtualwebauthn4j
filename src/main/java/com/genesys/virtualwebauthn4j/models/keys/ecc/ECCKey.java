package com.genesys.virtualwebauthn4j.models.keys.ecc;


import com.genesys.virtualwebauthn4j.WebAuthnUtil;
import com.genesys.virtualwebauthn4j.models.keys.SigningKey;

import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

public class ECCKey implements SigningKey {
    private final KeyPair keyPair;

    private static final int eccType = 3;
    private static final int eccP256Curve = 1;
    public static final int eccSHA256Algo = -7;

    public ECCKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
            keyPairGenerator.initialize(ecSpec, new SecureRandom());
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] KeyData() {
        ECPublicKey eccPublicKey = (ECPublicKey) keyPair.getPublic();
        ECCKeyInfo eccKeyInfo = new ECCKeyInfo(
                eccType,
                eccSHA256Algo,
                eccP256Curve,
                eccPublicKey.getW().getAffineX().toByteArray(),
                eccPublicKey.getW().getAffineY().toByteArray()
        );
        return WebAuthnUtil.marshalCbor(eccKeyInfo);
    }

    @Override
    public byte[] Sign(byte[] data) {
        try {
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(keyPair.getPrivate());
            signature.update(data);
            return signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }
}
