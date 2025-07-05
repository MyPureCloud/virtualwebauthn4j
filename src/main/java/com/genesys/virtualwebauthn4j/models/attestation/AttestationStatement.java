package com.genesys.virtualwebauthn4j.models.attestation;

public record AttestationStatement(int alg, byte[] sig) {
}
