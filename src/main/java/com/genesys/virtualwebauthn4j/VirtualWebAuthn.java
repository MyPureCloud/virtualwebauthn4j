package com.genesys.virtualwebauthn4j;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.genesys.virtualwebauthn4j.models.ClientData;
import com.genesys.virtualwebauthn4j.models.RelyingParty;
import com.genesys.virtualwebauthn4j.models.assertion.AssertionOptions;
import com.genesys.virtualwebauthn4j.models.assertion.AssertionOptionsValues;
import com.genesys.virtualwebauthn4j.models.assertion.AssertionResponse;
import com.genesys.virtualwebauthn4j.models.assertion.AssertionResult;
import com.genesys.virtualwebauthn4j.models.attestation.*;
import com.genesys.virtualwebauthn4j.models.authenticator.Authenticator;
import com.genesys.virtualwebauthn4j.models.authenticator.Credential;
import com.genesys.virtualwebauthn4j.models.keys.SigningKey;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import static com.genesys.virtualwebauthn4j.WebAuthnUtil.appendBytes;
import static com.genesys.virtualwebauthn4j.models.keys.ecc.ECCKey.eccSHA256Algo;
import static com.genesys.virtualwebauthn4j.models.keys.rsa.RSAKey.rsaSHA256Algo;

public class VirtualWebAuthn {

    public static AttestationOptions parseAttestationOptions(String str) {
        AttestationOptionsValues values;
        try {
            values = WebAuthnUtil.objectMapper.readValue(str, AttestationOptionsValues.class);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        if (values.publicKey() != null) {
            values = values.publicKey();
        }

        byte[] decodedUserId = WebAuthnUtil.decodeBase64(values.user().id());

        if (values.challenge() == null || values.challenge().isEmpty()) {
            throw new IllegalStateException("challenge is required");
        }

        Set<String> excludeCredentials = values.excludeCredentials() == null
                ? new HashSet<>()
                : values
                .excludeCredentials().stream().map(cred -> {
                    if (cred.id() == null || cred.id().isEmpty()) {
                        throw new IllegalStateException("credential id is required");
                    }
                    return cred.id();
                }).collect(Collectors.toSet());

        return new AttestationOptions(
                WebAuthnUtil.decodeBase64(values.challenge()),
                excludeCredentials,
                values.rp().id(),
                values.rp().name(),
                new String(decodedUserId),
                values.user().name(),
                values.user().displayName()
        );
    }

    public static String createAttestationResponse(
            RelyingParty rp,
            Authenticator auth,
            Credential cred,
            AttestationOptions options
    ) {
        ClientData clientData = new ClientData(
                "webauthn.create",
                WebAuthnUtil.encodeBase64(options.challenge()),
                rp.origin()
        );

        byte[] clientDataJson;
        try {
            clientDataJson = WebAuthnUtil.objectMapper.writeValueAsBytes(clientData);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        String clientDataJSONEncoded = WebAuthnUtil.encodeBase64(clientDataJson);

        byte[] credData = new byte[0];
        credData = appendBytes(credData, auth.getAaguid());
        credData = appendBytes(credData, WebAuthnUtil.bigEndianBytes(cred.getId().length, 2));
        credData = appendBytes(credData, cred.getId());
        credData = appendBytes(credData, cred.getKey().signingKey().KeyData());

        byte[] rpIdHash = WebAuthnUtil.sha256(rp.id().getBytes(StandardCharsets.UTF_8));

        byte flags = WebAuthnUtil.authenticatorDataFlags(
                !auth.getOptions().userNotPresent(),
                !auth.getOptions().userNotVerified(),
                true,
                false
        );

        byte[] authData = new byte[0];
        authData = appendBytes(authData, rpIdHash);
        authData = appendBytes(authData, flags);
        authData = appendBytes(authData, WebAuthnUtil.bigEndianBytes(cred.getCounter(), 4));
        authData = appendBytes(authData, credData);


        byte[] clientDataJsonHashed = WebAuthnUtil.sha256(clientDataJson);
        byte[] verifyData = appendBytes(authData, clientDataJsonHashed);

        SigningKey key = cred.getKey().signingKey();
        byte[] sig = key.Sign(verifyData);

        int algo;
        switch (cred.getKey().type()) {
            case ECC -> algo = eccSHA256Algo;
            case RSA -> algo = rsaSHA256Algo;
            default -> throw new IllegalStateException("Unexpected key type: " + cred.getKey().type());
        }

        AttestationObject attestationObject = new AttestationObject(
                "packed",
                authData,
                new AttestationStatement(algo, sig)
        );
        byte[] attestationObjectBytes = WebAuthnUtil.marshalCbor(attestationObject);
        String attestationObjectEncoded = WebAuthnUtil.encodeBase64(attestationObjectBytes);

        String credIdEncoded = WebAuthnUtil.encodeBase64(cred.getId());

        AttestationResponse attestationResponse = new AttestationResponse(
                attestationObjectEncoded,
                clientDataJSONEncoded
        );

        AttestationResult attestationResult = new AttestationResult(
                "public-key",
                credIdEncoded,
                credIdEncoded,
                attestationResponse
        );

        try {
            return WebAuthnUtil.objectMapper.writeValueAsString(attestationResult);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    public static AssertionOptions parseAssertionOptions(String str) {
        AssertionOptionsValues values;
        try {
            values = WebAuthnUtil.objectMapper.readValue(str, AssertionOptionsValues.class);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }

        if (values.publicKey() != null) {
            values = values.publicKey();
        }

        if (values.challenge() == null || values.challenge().isEmpty()) {
            throw new IllegalArgumentException("Challenge cannot be null or empty");
        }

        Set<String> allowCredentialIds = new HashSet<>();
        if (values.allowCredentials() != null) {
            allowCredentialIds = values.allowCredentials().stream().map(cred -> {
                if (cred.id() == null || cred.id().isEmpty()) {
                    throw new IllegalArgumentException("Credential ID in allowCredentials cannot be empty");
                }
                return cred.id();
            }).collect(Collectors.toSet());
        }

        return new AssertionOptions(
                WebAuthnUtil.decodeBase64(values.challenge()),
                allowCredentialIds,
                values.rpId()
        );
    }

    public static String createAssertionResponse(
            RelyingParty rp,
            Authenticator auth,
            Credential cred,
            AssertionOptions options
    ) {
        ClientData clientData = new ClientData(
                "webauthn.get",
                WebAuthnUtil.encodeBase64(options.challenge()),
                rp.origin()
        );

        byte[] clientDataJson;
        try {
            clientDataJson = WebAuthnUtil.objectMapper.writeValueAsBytes(clientData);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        String clientDataJsonEncoded = WebAuthnUtil.encodeBase64(clientDataJson);

        byte[] rpIdHash = WebAuthnUtil.sha256(rp.id().getBytes());
        byte flags = WebAuthnUtil.authenticatorDataFlags(
                !auth.getOptions().userNotPresent(),
                !auth.getOptions().userNotVerified(),
                false,
                false
        );

        byte[] authData = new byte[0];
        authData = WebAuthnUtil.appendBytes(authData, rpIdHash);
        authData = WebAuthnUtil.appendBytes(authData, flags);
        authData = WebAuthnUtil.appendBytes(authData, WebAuthnUtil.bigEndianBytes(cred.getCounter(), 4));
        String authDataEncoded = WebAuthnUtil.encodeBase64(authData);

        byte[] clientDataJsonHashed = WebAuthnUtil.sha256(clientDataJson);
        byte[] verifyData = WebAuthnUtil.appendBytes(authData, clientDataJsonHashed);

        byte[] sig = cred.getKey().signingKey().Sign(verifyData);

        String credIdEncoded = WebAuthnUtil.encodeBase64(cred.getId());

        AssertionResponse assertionResponse = new AssertionResponse(
                authDataEncoded,
                clientDataJsonEncoded,
                WebAuthnUtil.encodeBase64(sig),
                WebAuthnUtil.encodeBase64(auth.getOptions().userHandle())
        );

        AssertionResult assertionResult = new AssertionResult(
                "public-key",
                credIdEncoded,
                credIdEncoded,
                assertionResponse
        );

        try {
            return WebAuthnUtil.objectMapper.writeValueAsString(assertionResult);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
