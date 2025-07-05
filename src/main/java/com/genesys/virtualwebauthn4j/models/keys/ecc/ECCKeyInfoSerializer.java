package com.genesys.virtualwebauthn4j.models.keys.ecc;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;

import java.io.IOException;

public class ECCKeyInfoSerializer extends StdSerializer<ECCKeyInfo> {
    public ECCKeyInfoSerializer(Class<ECCKeyInfo> t) {
        super(t);
    }

    @Override
    public void serialize(
            ECCKeyInfo value,
            JsonGenerator jgen,
            SerializerProvider provider
    ) throws IOException {
        ((CBORGenerator) jgen).writeStartObject(5);

        jgen.writeFieldId(1);
        jgen.writeNumber(value.type());

        jgen.writeFieldId(3);
        jgen.writeNumber(value.algorithm());

        jgen.writeFieldId(-1);
        jgen.writeNumber(value.curve());

        jgen.writeFieldId(-2);
        jgen.writeBinary(value.x());

        jgen.writeFieldId(-3);
        jgen.writeBinary(value.y());

        jgen.writeEndObject();
    }
}