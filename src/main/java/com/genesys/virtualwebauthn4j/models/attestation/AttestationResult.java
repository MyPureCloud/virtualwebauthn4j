package com.genesys.virtualwebauthn4j.models.attestation;

public record AttestationResult(String type, String id, String rawId, AttestationResponse response) {
}
