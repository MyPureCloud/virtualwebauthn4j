package com.genesys.virtualwebauthn4j.models.attestation;

import java.util.Collection;

public record AttestationOptionsValues(
        String challenge,
        Collection<AttestationOptionsExcludeCredential> excludeCredentials,
        AttestationOptionsRelyingParty rp,
        AttestationOptionsUser user,
        AttestationOptionsValues publicKey
) {
}
