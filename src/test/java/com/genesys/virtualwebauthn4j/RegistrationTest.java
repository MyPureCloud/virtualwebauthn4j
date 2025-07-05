package com.genesys.virtualwebauthn4j;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.genesys.virtualwebauthn4j.models.RelyingParty;
import com.genesys.virtualwebauthn4j.models.assertion.AssertionOptions;
import com.genesys.virtualwebauthn4j.models.assertion.AssertionOptionsValues;
import com.genesys.virtualwebauthn4j.models.assertion.AssertionOptionsAllowCredential;
import com.genesys.virtualwebauthn4j.models.assertion.AssertionResult;
import com.genesys.virtualwebauthn4j.models.attestation.AttestationOptions;
import com.genesys.virtualwebauthn4j.models.attestation.AttestationOptionsValues;
import com.genesys.virtualwebauthn4j.models.attestation.AttestationOptionsRelyingParty;
import com.genesys.virtualwebauthn4j.models.attestation.AttestationOptionsUser;
import com.genesys.virtualwebauthn4j.models.attestation.AttestationResult;
import com.genesys.virtualwebauthn4j.models.authenticator.Authenticator;
import com.genesys.virtualwebauthn4j.models.authenticator.Credential;
import com.genesys.virtualwebauthn4j.models.keys.KeyType;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.*;

public class RegistrationTest {

    @Test
    public void testWebAuthnRegistrationAndLoginWithRSA() throws JsonProcessingException {
        // Setup test data
        RelyingParty rp = new RelyingParty("local.com", "Genesys Cloud", "https://login.local.com");
        Authenticator authenticator = new Authenticator();
        Credential credential = new Credential(KeyType.RSA);

        // Create mock attestation options (normally from server)
        AttestationOptions attestationOptions = createMockAttestationOptions(rp, "test-user-123");
        
        // Test attestation (registration) flow
        String attestationResponseJson = VirtualWebAuthn.createAttestationResponse(rp, authenticator, credential, attestationOptions);
        assertNotNull(attestationResponseJson);
        assertFalse(attestationResponseJson.isEmpty());
        
        // Parse and validate attestation response
        AttestationResult attestationResult = WebAuthnUtil.objectMapper.readValue(attestationResponseJson, AttestationResult.class);
        assertNotNull(attestationResult);
        assertEquals("public-key", attestationResult.type());
        assertNotNull(attestationResult.id());
        assertNotNull(attestationResult.response());
        assertNotNull(attestationResult.response().attestationObject());
        assertNotNull(attestationResult.response().clientDataJSON());
        
        // Add credential to authenticator for login flow
        authenticator.addCredential(credential);
        
        // Create mock assertion options (normally from server)
        AssertionOptions assertionOptions = createMockAssertionOptions(rp, credential);
        
        // Test assertion (login) flow
        String assertionResponseJson = VirtualWebAuthn.createAssertionResponse(rp, authenticator, credential, assertionOptions);
        assertNotNull(assertionResponseJson);
        assertFalse(assertionResponseJson.isEmpty());
        
        // Parse and validate assertion response
        AssertionResult assertionResult = WebAuthnUtil.objectMapper.readValue(assertionResponseJson, AssertionResult.class);
        assertNotNull(assertionResult);
        assertEquals("public-key", assertionResult.type());
        assertNotNull(assertionResult.id());
        assertNotNull(assertionResult.response());
        assertNotNull(assertionResult.response().authenticatorData());
        assertNotNull(assertionResult.response().clientDataJSON());
        assertNotNull(assertionResult.response().signature());
        
        // Verify the credential IDs match between attestation and assertion
        assertEquals(attestationResult.id(), assertionResult.id());
    }
    
    @Test
    public void testWebAuthnRegistrationAndLoginWithECC() throws JsonProcessingException {
        // Setup test data
        RelyingParty rp = new RelyingParty("example.com", "Example Corp", "https://example.com");
        Authenticator authenticator = new Authenticator();
        Credential credential = new Credential(KeyType.ECC);

        // Create mock attestation options (normally from server)
        AttestationOptions attestationOptions = createMockAttestationOptions(rp, "test-user-456");
        
        // Test attestation (registration) flow
        String attestationResponseJson = VirtualWebAuthn.createAttestationResponse(rp, authenticator, credential, attestationOptions);
        assertNotNull(attestationResponseJson);
        assertFalse(attestationResponseJson.isEmpty());
        
        // Parse and validate attestation response
        AttestationResult attestationResult = WebAuthnUtil.objectMapper.readValue(attestationResponseJson, AttestationResult.class);
        assertNotNull(attestationResult);
        assertEquals("public-key", attestationResult.type());
        
        // Add credential to authenticator for login flow
        authenticator.addCredential(credential);
        
        // Create mock assertion options (normally from server)
        AssertionOptions assertionOptions = createMockAssertionOptions(rp, credential);
        
        // Test assertion (login) flow
        String assertionResponseJson = VirtualWebAuthn.createAssertionResponse(rp, authenticator, credential, assertionOptions);
        assertNotNull(assertionResponseJson);
        assertFalse(assertionResponseJson.isEmpty());
        
        // Parse and validate assertion response
        AssertionResult assertionResult = WebAuthnUtil.objectMapper.readValue(assertionResponseJson, AssertionResult.class);
        assertNotNull(assertionResult);
        assertEquals("public-key", assertionResult.type());
        
        // Verify the credential IDs match between attestation and assertion
        assertEquals(attestationResult.id(), assertionResult.id());
    }
    
    @Test
    public void testAttestationOptionsParsingFromJson() throws JsonProcessingException {
        // Create mock attestation options JSON (what would come from server)
        AttestationOptionsValues optionsValues = new AttestationOptionsValues(
            WebAuthnUtil.encodeBase64("test-challenge-123".getBytes()),
            Collections.emptyList(),
            new AttestationOptionsRelyingParty("local.com", "Test RP"),
            new AttestationOptionsUser(
                WebAuthnUtil.encodeBase64("user-123".getBytes()),
                "testuser",
                "Test User"
            ),
            null
        );
        
        String optionsJson = WebAuthnUtil.objectMapper.writeValueAsString(optionsValues);
        
        // Test parsing
        AttestationOptions parsedOptions = VirtualWebAuthn.parseAttestationOptions(optionsJson);
        assertNotNull(parsedOptions);
        assertEquals("local.com", parsedOptions.rpId());
        assertEquals("Test RP", parsedOptions.rpName());
        assertEquals("user-123", parsedOptions.user());
        assertEquals("testuser", parsedOptions.userName());
        assertEquals("Test User", parsedOptions.userDisplayName());
        assertArrayEquals("test-challenge-123".getBytes(), parsedOptions.challenge());
    }
    
    @Test
    public void testAssertionOptionsParsingFromJson() throws JsonProcessingException {
        // Create mock assertion options JSON (what would come from server)
        AssertionOptionsValues optionsValues = new AssertionOptionsValues(
            WebAuthnUtil.encodeBase64("test-challenge-456".getBytes()),
            Collections.singletonList(new AssertionOptionsAllowCredential("public-key", "test-credential-id")),
            "local.com",
            null
        );
        
        String optionsJson = WebAuthnUtil.objectMapper.writeValueAsString(optionsValues);
        
        // Test parsing
        AssertionOptions parsedOptions = VirtualWebAuthn.parseAssertionOptions(optionsJson);
        assertNotNull(parsedOptions);
        assertEquals("local.com", parsedOptions.rpId());
        assertArrayEquals("test-challenge-456".getBytes(), parsedOptions.challenge());
        assertTrue(parsedOptions.allowCredentials().contains("test-credential-id"));
    }
    
    private AttestationOptions createMockAttestationOptions(RelyingParty rp, String userId) {
        byte[] challenge = WebAuthnUtil.randomBytes(32);
        return new AttestationOptions(
            challenge,
            new HashSet<>(), // No excluded credentials
            rp.id(),
            rp.name(),
            userId,
            "testuser",
            "Test User"
        );
    }
    
    private AssertionOptions createMockAssertionOptions(RelyingParty rp, Credential credential) {
        byte[] challenge = WebAuthnUtil.randomBytes(32);
        return new AssertionOptions(
            challenge,
            Collections.singleton(WebAuthnUtil.encodeBase64(credential.getId())),
            rp.id()
        );
    }
}
