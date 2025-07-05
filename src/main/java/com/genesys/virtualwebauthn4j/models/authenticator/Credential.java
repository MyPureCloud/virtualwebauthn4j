package com.genesys.virtualwebauthn4j.models.authenticator;

import com.genesys.virtualwebauthn4j.models.keys.Key;
import com.genesys.virtualwebauthn4j.models.keys.KeyType;
import com.genesys.virtualwebauthn4j.models.keys.ecc.ECCKey;
import com.genesys.virtualwebauthn4j.models.keys.rsa.RSAKey;

import java.util.Arrays;
import java.util.Objects;

import static com.genesys.virtualwebauthn4j.WebAuthnUtil.randomBytes;

public class Credential {
    private byte[] id;
    private Key key;
    private int counter;

    public Credential(byte[] id, Key key, int counter) {
        this.id = id;
        this.key = key;
        this.counter = counter;
    }

    public Credential(KeyType type) {
        this.id = randomBytes(32);

        switch (type) {
            case ECC:
                this.key = new Key(type, new ECCKey());
                break;
            case RSA:
                this.key = new Key(type, new RSAKey());
                break;
            default:
                throw new IllegalArgumentException("Unsupported key type: " + type);
        }
    }

    public byte[] getId() {
        return id;
    }

    public void setId(byte[] id) {
        this.id = id;
    }

    public Key getKey() {
        return key;
    }

    public void setKey(Key key) {
        this.key = key;
    }

    public int getCounter() {
        return counter;
    }

    public void setCounter(int counter) {
        this.counter = counter;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (Credential) obj;
        return Arrays.equals(this.id, that.id) &&
                Objects.equals(this.key, that.key) &&
                this.counter == that.counter;
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(id), key, counter);
    }

    @Override
    public String toString() {
        return "Credential[" +
                "id=" + Arrays.toString(id) + ", " +
                "key=" + key + ", " +
                "counter=" + counter + ']';
    }
}
