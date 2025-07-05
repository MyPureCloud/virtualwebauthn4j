package com.genesys.virtualwebauthn4j.models.assertion;

public record AssertionResult(String type, String id, String rawId, AssertionResponse response) {
}
