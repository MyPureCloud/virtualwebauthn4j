package com.genesys.virtualwebauthn4j.models.attestation;

import java.util.Collection;

public record AttestationOptions(
        byte[] challenge,
        Collection<String> excludeCredentials,
        String rpId,
        String rpName,
        String user,
        String userName,
        String userDisplayName
) {
}
