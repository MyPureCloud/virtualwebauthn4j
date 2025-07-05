package com.genesys.virtualwebauthn4j.models.keys.rsa;

public record RSAKeyInfo(int type, int algorithm, byte[] modulus, byte[] exponent) {
}
