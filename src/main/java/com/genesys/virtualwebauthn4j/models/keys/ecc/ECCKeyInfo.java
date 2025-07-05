package com.genesys.virtualwebauthn4j.models.keys.ecc;

public record ECCKeyInfo(int type, int algorithm, int curve, byte[]x, byte[] y) {
}
