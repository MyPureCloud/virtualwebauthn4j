package com.genesys.virtualwebauthn4j.models.authenticator;

public record AuthenticatorOptions(byte[] userHandle, boolean userNotPresent, boolean userNotVerified) {
}
