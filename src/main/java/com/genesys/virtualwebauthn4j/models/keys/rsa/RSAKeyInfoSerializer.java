package com.genesys.virtualwebauthn4j.models.keys.rsa;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;

import java.io.IOException;

public class RSAKeyInfoSerializer extends StdSerializer<RSAKeyInfo> {
    public RSAKeyInfoSerializer(Class<RSAKeyInfo> t) {
        super(t);
    }

    @Override
    public void serialize(
            RSAKeyInfo value,
            JsonGenerator jgen,
            SerializerProvider provider
    ) throws IOException {
        ((CBORGenerator) jgen).writeStartObject(4);

        jgen.writeFieldId(1);
        jgen.writeNumber(value.type());

        jgen.writeFieldId(3);
        jgen.writeNumber(value.algorithm());

        jgen.writeFieldId(-1);
        jgen.writeBinary(value.modulus());

        jgen.writeFieldId(-2);
        jgen.writeBinary(value.exponent());

        jgen.writeEndObject();
    }
}