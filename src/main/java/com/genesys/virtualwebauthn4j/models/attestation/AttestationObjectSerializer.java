package com.genesys.virtualwebauthn4j.models.attestation;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;

import java.io.IOException;

public class AttestationObjectSerializer extends StdSerializer<AttestationObject> {
    public AttestationObjectSerializer(Class<AttestationObject> t) {
        super(t);
    }

    @Override
    public void serialize(
            AttestationObject value,
            JsonGenerator jgen,
            SerializerProvider provider
    ) throws IOException {
        ((CBORGenerator) jgen).writeStartObject(3);

        jgen.writeFieldName("attStmt");
        ((CBORGenerator) jgen).writeStartObject(2);
        jgen.writeFieldName("alg");
        jgen.writeNumber(value.attStmt().alg());
        jgen.writeFieldName("sig");
        jgen.writeBinary(value.attStmt().sig());
        jgen.writeEndObject();

        jgen.writeFieldName("authData");
        jgen.writeBinary(value.authData());

        jgen.writeFieldName("fmt");
        jgen.writeString(value.fmt());

        jgen.writeEndObject();
    }
}