package com.genesys.virtualwebauthn4j.models.assertion;

import java.util.Collection;

public record AssertionOptionsValues(
        String challenge,
        Collection<AssertionOptionsAllowCredential> allowCredentials,
        String rpId,
        AssertionOptionsValues publicKey
) {
}
