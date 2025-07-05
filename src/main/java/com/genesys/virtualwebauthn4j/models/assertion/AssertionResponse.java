package com.genesys.virtualwebauthn4j.models.assertion;

public record AssertionResponse(String authenticatorData, String clientDataJSON, String signature, String userHandle) {
}
