package com.genesys.virtualwebauthn4j;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import com.genesys.virtualwebauthn4j.models.attestation.AttestationObjectSerializer;
import com.genesys.virtualwebauthn4j.models.keys.ecc.ECCKeyInfo;
import com.genesys.virtualwebauthn4j.models.keys.ecc.ECCKeyInfoSerializer;
import com.genesys.virtualwebauthn4j.models.keys.rsa.RSAKeyInfo;
import com.genesys.virtualwebauthn4j.models.attestation.AttestationObject;
import com.genesys.virtualwebauthn4j.models.keys.rsa.RSAKeyInfoSerializer;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class WebAuthnUtil {
    public static final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    public static final Base64.Decoder decoder = Base64.getUrlDecoder();
    public static final ObjectMapper objectMapper = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    public static byte[] randomBytes(int length) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[length];

        secureRandom.nextBytes(randomBytes);
        return randomBytes;
    }

    public static String encodeBase64(byte[] input) {
        return encoder.encodeToString(input);
    }

    public static byte[] decodeBase64(String input) {
        return decoder.decode(input);
    }

    public static byte[] bigEndianBytes(int value, int length) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            int shift = (length - i - 1) * 8;
            bytes[i] = (byte) ((value >> shift) & 0xFF);
        }
        return bytes;
    }

    public static byte[] sha256(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] appendBytes(byte[] originalArray, byte... additionalBytes) {
        byte[] resultArray = new byte[originalArray.length + additionalBytes.length];
        System.arraycopy(originalArray, 0, resultArray, 0, originalArray.length);
        System.arraycopy(additionalBytes, 0, resultArray, originalArray.length, additionalBytes.length);
        return resultArray;
    }

    public static byte[] marshalCbor(Object v) {
        CBORFactory cborFactory = new CBORFactory().configure(CBORGenerator.Feature.WRITE_MINIMAL_INTS, true);
        ObjectMapper cborMapper = new ObjectMapper(cborFactory);

        SimpleModule module = new SimpleModule();
        module.addSerializer(new AttestationObjectSerializer(AttestationObject.class));
        module.addSerializer(new RSAKeyInfoSerializer(RSAKeyInfo.class));
        module.addSerializer(new ECCKeyInfoSerializer(ECCKeyInfo.class));
        cborMapper.registerModule(module);

        try {
            return cborMapper.writeValueAsBytes(v);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to encode to CBOR", e);
        }
    }

    public static byte authenticatorDataFlags(boolean userPresent, boolean userVerified, boolean attestation, boolean extensions) {
        byte flags = 0;
        if (userPresent) {
            flags |= 1 << 0;
        }
        if (userVerified) {
            flags |= 1 << 2;
        }
        if (attestation) {
            flags |= 1 << 6;
        }
        if (extensions) { // extensions not supported yet
            flags |= 1 << 7;
        }
        return flags;
    }
}
