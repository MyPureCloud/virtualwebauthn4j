package com.genesys.virtualwebauthn4j.models.assertion;

import java.util.Collection;

public record AssertionOptions(byte[] challenge, Collection<String> allowCredentials, String rpId) {
}
