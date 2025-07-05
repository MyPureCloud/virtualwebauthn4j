package com.genesys.virtualwebauthn4j.models.attestation;

public record AttestationObject(String fmt, byte[] authData, AttestationStatement attStmt) {
}
