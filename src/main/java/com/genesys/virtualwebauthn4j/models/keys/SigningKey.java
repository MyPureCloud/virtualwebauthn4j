package com.genesys.virtualwebauthn4j.models.keys;

public interface SigningKey {
    byte[] KeyData();
    byte[] Sign(byte[] data);
}
