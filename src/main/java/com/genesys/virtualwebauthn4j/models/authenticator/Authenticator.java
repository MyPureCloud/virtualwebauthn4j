package com.genesys.virtualwebauthn4j.models.authenticator;


import com.genesys.virtualwebauthn4j.WebAuthnUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Objects;

public final class Authenticator {
    private AuthenticatorOptions options;
    private byte[] aaguid;
    private Collection<Credential> credentials;

    public Authenticator() {
        this(new AuthenticatorOptions(new byte[0], false, false));
    }

    public Authenticator(AuthenticatorOptions options) {
        this.options = options;
        this.aaguid = WebAuthnUtil.randomBytes(16);
        this.credentials = new ArrayList<>();
    }

    public Authenticator(AuthenticatorOptions options, byte[] aaguid, Collection<Credential> credentials) {
        this.options = options;
        this.aaguid = aaguid;
        this.credentials = credentials;
    }

    public AuthenticatorOptions getOptions() {
        return options;
    }

    public void setOptions(AuthenticatorOptions options) {
        this.options = options;
    }

    public byte[] getAaguid() {
        return aaguid;
    }

    public void setAaguid(byte[] aaguid) {
        this.aaguid = aaguid;
    }

    public Collection<Credential> getCredentials() {
        return credentials;
    }

    public void setCredentials(Collection<Credential> credentials) {
        this.credentials = credentials;
    }

    public void addCredential(Credential credential) {
        credentials.add(credential);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (Authenticator) obj;
        return Objects.equals(this.options, that.options) &&
                Arrays.equals(this.aaguid, that.aaguid) &&
                Objects.equals(this.credentials, that.credentials);
    }

    @Override
    public int hashCode() {
        return Objects.hash(options, Arrays.hashCode(aaguid), credentials);
    }

    @Override
    public String toString() {
        return "Authenticator[" +
                "options=" + options + ", " +
                "aaguid=" + Arrays.toString(aaguid) + ", " +
                "credentials=" + credentials + ']';
    }
}
