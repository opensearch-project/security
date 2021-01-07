package com.amazon.dlic.auth.http.jwt.authtoken.api.jackson;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.xcontent.DeprecationHandler;
import org.elasticsearch.common.xcontent.LoggingDeprecationHandler;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.ToXContent.MapParams;
import org.elasticsearch.common.xcontent.ToXContent.Params;
import org.elasticsearch.common.xcontent.XContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentGenerator;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;


public class JacksonXContent implements XContent {
    private final static Logger log = LogManager.getLogger(JacksonXContent.class);

    public static JsonNode toJsonNode(ToXContent toXContent) throws IOException {
        return toJsonNode(toXContent, new MapParams(Collections.emptyMap()));
    }

    public static JsonNode toJsonNode(ToXContent toXContent, Params params) throws IOException {
        try (XContentBuilder builder = XContentBuilder.builder(new JacksonXContent())) {
            if (toXContent.isFragment()) {
                builder.startObject();
            }
            toXContent.toXContent(builder, params);
            if (toXContent.isFragment()) {
                builder.endObject();
            }

            Generator generator = (Generator) builder.generator();
            return generator.getTopLevelObject();
        }
    }

    public JacksonXContent() {
    }

    @Override
    public XContentType type() {
        return null;
    }

    @Override
    public byte streamSeparator() {
        return 0;
    }

    @Override
    public XContentGenerator createGenerator(OutputStream os, Set<String> includes, Set<String> excludes) throws IOException {
        return new Generator(includes, excludes);
    }

    @Override
    public XContentParser createParser(NamedXContentRegistry xContentRegistry, DeprecationHandler deprecationHandler, String content)
            throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public XContentParser createParser(NamedXContentRegistry xContentRegistry, DeprecationHandler deprecationHandler, InputStream is)
            throws IOException {
        throw new UnsupportedOperationException();

    }

    @Override
    public XContentParser createParser(NamedXContentRegistry xContentRegistry, DeprecationHandler deprecationHandler, byte[] data)
            throws IOException {
        throw new UnsupportedOperationException();

    }

    @Override
    public XContentParser createParser(NamedXContentRegistry xContentRegistry, DeprecationHandler deprecationHandler, byte[] data, int offset,
                                       int length) throws IOException {
        throw new UnsupportedOperationException();

    }

    @Override
    public XContentParser createParser(NamedXContentRegistry xContentRegistry, DeprecationHandler deprecationHandler, Reader reader)
            throws IOException {
        throw new UnsupportedOperationException();

    }

    static class Generator implements XContentGenerator {

        // TODO:
        private Set<String> includes;
        private Set<String> excludes;
        private List<JsonNode> objectStack = new ArrayList<>();
        private List<JsonNode> topLevelObjects = new ArrayList<>();
        private String currentKey = null;

        Generator(Set<String> includes, Set<String> excludes) {
            this.includes = includes;
            this.excludes = excludes;
        }

        @Override
        public void close() throws IOException {

        }

        @Override
        public void flush() throws IOException {

        }

        @Override
        public XContentType contentType() {
            return null;
        }

        @Override
        public void usePrettyPrint() {

        }

        @Override
        public boolean isPrettyPrint() {
            return false;
        }

        @Override
        public void usePrintLineFeedAtEnd() {

        }

        @Override
        public void writeStartObject() throws IOException {
            ObjectNode objectNode = JsonNodeFactory.instance.objectNode();

            this.objectStack.add(addObject(objectNode));
        }

        @Override
        public void writeEndObject() throws IOException {
            pop();
        }

        @Override
        public void writeStartArray() throws IOException {
            ArrayNode arrayNode = JsonNodeFactory.instance.arrayNode();

            this.objectStack.add(addObject(arrayNode));
        }

        @Override
        public void writeEndArray() throws IOException {
            pop();
        }

        @Override
        public void writeFieldName(String name) throws IOException {
            this.currentKey = name;
        }

        @Override
        public void writeNull() throws IOException {
            addObject(JsonNodeFactory.instance.nullNode());
        }

        @Override
        public void writeNullField(String name) throws IOException {
            addObject(name, JsonNodeFactory.instance.nullNode());
        }

        @Override
        public void writeBooleanField(String name, boolean value) throws IOException {
            addObject(name, JsonNodeFactory.instance.booleanNode(value));
        }

        @Override
        public void writeBoolean(boolean value) throws IOException {
            addObject(JsonNodeFactory.instance.booleanNode(value));
        }

        @Override
        public void writeNumberField(String name, double value) throws IOException {
            addObject(name, JsonNodeFactory.instance.numberNode(value));
        }

        @Override
        public void writeNumber(double value) throws IOException {
            addObject(JsonNodeFactory.instance.numberNode(value));
        }

        @Override
        public void writeNumberField(String name, float value) throws IOException {
            addObject(name, JsonNodeFactory.instance.numberNode(value));
        }

        @Override
        public void writeNumber(float value) throws IOException {
            addObject(JsonNodeFactory.instance.numberNode(value));
        }

        @Override
        public void writeNumberField(String name, int value) throws IOException {
            addObject(name, JsonNodeFactory.instance.numberNode(value));
        }

        @Override
        public void writeNumber(int value) throws IOException {
            addObject(JsonNodeFactory.instance.numberNode(value));
        }

        @Override
        public void writeNumberField(String name, long value) throws IOException {
            addObject(name, JsonNodeFactory.instance.numberNode(value));
        }

        @Override
        public void writeNumber(long value) throws IOException {
            addObject(JsonNodeFactory.instance.numberNode(value));
        }

        @Override
        public void writeNumber(short value) throws IOException {
            addObject(JsonNodeFactory.instance.numberNode(value));
        }

        @Override
        public void writeNumber(BigInteger value) throws IOException {
            addObject(JsonNodeFactory.instance.numberNode(value));
        }

        @Override
        public void writeNumberField(String name, BigInteger value) throws IOException {
            addObject(name, JsonNodeFactory.instance.numberNode(value));
        }

        @Override
        public void writeNumber(BigDecimal value) throws IOException {
            addObject(JsonNodeFactory.instance.numberNode(value));
        }

        @Override
        public void writeNumberField(String name, BigDecimal value) throws IOException {
            addObject(name, JsonNodeFactory.instance.numberNode(value));
        }

        @Override
        public void writeStringField(String name, String value) throws IOException {
            addObject(name, JsonNodeFactory.instance.textNode(value));
        }

        @Override
        public void writeString(String value) throws IOException {
            addObject(JsonNodeFactory.instance.textNode(value));
        }

        @Override
        public void writeString(char[] text, int offset, int len) throws IOException {
            addObject(JsonNodeFactory.instance.textNode(new String(text, offset, len)));
        }

        @Override
        public void writeUTF8String(byte[] value, int offset, int length) throws IOException {
            addObject(JsonNodeFactory.instance.textNode(new String(value, offset, length, "UTF-8")));
        }

        @Override
        public void writeBinaryField(String name, byte[] value) throws IOException {
            addObject(name, JsonNodeFactory.instance.binaryNode(value));
        }

        @Override
        public void writeBinary(byte[] value) throws IOException {
            addObject(JsonNodeFactory.instance.binaryNode(value));
        }

        @Override
        public void writeBinary(byte[] value, int offset, int length) throws IOException {
            byte[] valueSection = new byte[length];
            System.arraycopy(value, offset, valueSection, 0, length);
            addObject(JsonNodeFactory.instance.binaryNode(value));
        }

        @SuppressWarnings("deprecation")
        @Override
        public void writeRawField(String name, InputStream value) throws IOException {
            if (!value.markSupported()) {
                value = new BufferedInputStream(value);
            }

            XContentType xContentType = XContentFactory.xContentType(value);

            writeRawField(name, value, xContentType);
        }

        @Override
        public void writeRawField(String name, InputStream value, XContentType xContentType) throws IOException {
            writeFieldName(name);
            writeRawValue(value, xContentType);
        }

        @Override
        public void writeRawValue(InputStream value, XContentType xContentType) throws IOException {
            try (XContentParser parser = XContentFactory.xContent(xContentType).createParser(NamedXContentRegistry.EMPTY,
                    LoggingDeprecationHandler.INSTANCE, value)) {
                parser.nextToken();
                copyCurrentStructure(parser);
            }
        }

        @Override
        public void copyCurrentStructure(XContentParser parser) throws IOException {
            int nestingDepth = 0;

            for (XContentParser.Token token = parser.currentToken(); token != null; token = parser.nextToken()) {
                switch (token) {
                    case FIELD_NAME:
                        writeFieldName(parser.currentName());
                        break;
                    case START_ARRAY:
                        writeStartArray();
                        nestingDepth++;
                        break;
                    case START_OBJECT:
                        writeStartObject();
                        nestingDepth++;
                        break;
                    case END_ARRAY:
                        writeEndArray();
                        nestingDepth--;
                        break;
                    case END_OBJECT:
                        writeEndObject();
                        nestingDepth--;
                        break;
                    default:
                        copyCurrentEvent(parser);
                }

                if (nestingDepth == 0 && token != XContentParser.Token.FIELD_NAME) {
                    return;
                }
            }

        }

        @Override
        public boolean isClosed() {
            return false;
        }

        JsonNode getTopLevelObject() {
            if (topLevelObjects.size() == 0) {
                return null;
            } else if (topLevelObjects.size() > 1) {
                log.warn("More than one top level object was produced. Using first one: " + this.topLevelObjects);
            }

            return this.topLevelObjects.get(0);
        }

        private JsonNode addObject(Object key, JsonNode object) throws IOException {
            JsonNode top = top();

            if (top == null) {
                this.topLevelObjects.add(object);
            } else if (top instanceof ArrayNode) {
                ((ArrayNode) top).add(object);
            } else if (top instanceof ObjectNode) {
                String keyString = String.valueOf(key);
                ((ObjectNode) top).set(keyString, object);
            } else {
                throw new IOException("Invalid object structure: " + top + " is not a container.");
            }

            return object;
        }

        private JsonNode addObject(JsonNode object) throws IOException {
            object = addObject(this.currentKey, object);
            this.currentKey = null;
            return object;
        }

        private JsonNode top() {
            if (this.objectStack.size() == 0) {
                return null;
            } else {
                return this.objectStack.get(this.objectStack.size() - 1);
            }
        }

        private JsonNode pop() {
            if (this.objectStack.size() == 0) {
                return null;
            } else {
                return this.objectStack.remove(this.objectStack.size() - 1);
            }
        }

    }
}

