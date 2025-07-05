
# VirtualWebAuthn4J

This library is a Java implementation of the Go package [virtualwebauthn](https://github.com/descope/virtualwebauthn). It provides a set of helper tools for testing full [WebAuthn](https://fidoalliance.org/fido2-2/fido2-web-authentication-webauthn) authentication flows in a [relying party](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party) WebAuthn server implementation without requiring a browser or an actual authenticator.

## Features

- Test both register/attestation and login/assertion flows
- Validate credential [creation](https://www.w3.org/TR/webauthn-2/#sctn-credentialcreationoptions-extension) and [request](https://www.w3.org/TR/webauthn-2/#sctn-credentialrequestoptions-extension) options
- Generate [attestation](https://www.w3.org/TR/webauthn-2/#authenticatorattestationresponse) and [assertion](https://www.w3.org/TR/webauthn-2/#authenticatorassertionresponse) responses
- Supports `ECC` and `RSA` keys with `SHA256`
- Supports `packed` attestation format

## Usage

### Setup

First we create mock entities to work with for running tests.

```java
// The relying party settings should mirror those on the actual WebAuthn server
RelyingParty rp = new RelyingParty("example.com", "Example Corp", "https://example.com");

// A mock authenticator that represents a security key or biometrics module
Authenticator authenticator = new Authenticator();

// Create a new credential that we'll try to register with the relying party
Credential credential = new Credential(KeyType.RSA);
```

### Register

Start a register flow with the relying party and get an `attestationOptions` JSON string that contains the serialized [credential creation options](https://www.w3.org/TR/webauthn-2/#sctn-credentialcreationoptions-extension):

```java
// Ask the server to start a register flow for a user. The server and user here
// are placeholders for whatever the system being tested uses.
String attestationOptions = server.beginRegistration(user);
```

Use the `ParseAttestationOptions` and `CreateAttestationResponse` functions to parse the `attestationOptions` string, ensure that it's valid, and generate an appropriate `attestationResponse` that should appear to have come from a browser's `navigator.credentials.create` call:

```java
// Parses the attestation options we got from the relying party to ensure they're valid
AttestationOptions attestationOptions = VirtualWebAuthn.parseAttestationOptions(attestationOptions);

// Creates an attestation response that we can send to the relying party as if it came from
// an actual browser and authenticator.
String attestationResponse = VirtualWebAuthn.createAttestationResponse(rp, authenticator, credential, attestationOptions);
```

We can now go back to the relying party with the `attestationResponse` and finish the register flow:

```java
// Finish the register flow by sending the attestation response. Again the server and
// user here are placeholders for whatever the system being tested uses.
server.finishRegistration(user, attestationResponse);


// Add the credential to the mock authenticator
authenticator.AddCredential(credential);
```