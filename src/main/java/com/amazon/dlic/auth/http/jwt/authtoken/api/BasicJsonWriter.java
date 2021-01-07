package com.amazon.dlic.auth.http.jwt.authtoken.api;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Collection;
import java.util.Map;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonGenerator;

public class BasicJsonWriter {

    public static String writeAsString(Object object) {
        try (StringWriter writer = new StringWriter(); JsonGenerator generator = jsonFactory.createGenerator(writer)) {
            new BasicJsonWriter(generator).write(object);

            generator.flush();
            writer.flush();

            return writer.toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static JsonFactory jsonFactory = new JsonFactory();

    private JsonGenerator generator;
    private int maxDepth = 20;

    public BasicJsonWriter(JsonGenerator generator) {
        this.generator = generator;
    }

    public void write(Object object) throws IOException {
        write(object, 0);
    }

    private void write(Object object, int depth) throws IOException {
        if (depth > maxDepth) {
            throw new JsonGenerationException("Max JSON depth exceeded", generator);
        }

        if (object instanceof Collection) {
            @SuppressWarnings("unchecked")
            Collection<Object> collection = (Collection<Object>) object;

            generator.writeStartArray();

            for (Object element : collection) {
                write(element, depth + 1);
            }

            generator.writeEndArray();
        } else if (object instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<Object, Object> map = (Map<Object, Object>) object;

            generator.writeStartObject();

            for (Map.Entry<Object, Object> entry : map.entrySet()) {
                generator.writeFieldName(String.valueOf(entry.getKey()));

                write(entry.getValue(), depth + 1);
            }

            generator.writeEndObject();
        } else if (object instanceof String) {
            generator.writeString((String) object);
        } else if (object instanceof Character) {
            generator.writeString(object.toString());
        } else if (object instanceof Integer) {
            generator.writeNumber(((Integer) object).intValue());
        } else if (object instanceof Long) {
            generator.writeNumber(((Long) object).longValue());
        } else if (object instanceof Short) {
            generator.writeNumber(((Short) object).shortValue());
        } else if (object instanceof Float) {
            generator.writeNumber(((Float) object).floatValue());
        } else if (object instanceof Double) {
            generator.writeNumber(((Double) object).doubleValue());
        } else if (object instanceof BigDecimal) {
            generator.writeNumber((BigDecimal) object);
        } else if (object instanceof BigInteger) {
            generator.writeNumber((BigInteger) object);
        } else if (object instanceof Number) {
            generator.writeNumber(object.toString());
        } else if (object instanceof Boolean) {
            generator.writeBoolean(((Boolean) object).booleanValue());
        } else if (object instanceof Enum) {
            generator.writeString(((Enum<?>) object).name());
        } else if (object == null) {
            generator.writeNull();
        } else {
            throw new JsonGenerationException("Unsupported object type: " + object, generator);
        }
    }
}

