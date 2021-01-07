package com.amazon.dlic.auth.http.jwt.authtoken.api;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

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

public class ObjectTreeXContent implements XContent {
    private final static Logger log = LogManager.getLogger(ObjectTreeXContent.class);

    public static Object toObjectTree(ToXContent toXContent) {
        return toObjectTree(toXContent, new MapParams(Collections.emptyMap()));
    }

    public static Object toObjectTree(ToXContent toXContent, Params params) {
        return toObjectTree(toXContent, params, () -> new HashMap<>());
    }

    public static Object toObjectTree(ToXContent toXContent, Params params, Supplier<Map<?, ?>> mapFactory) {
        try (XContentBuilder builder = XContentBuilder.builder(new ObjectTreeXContent(mapFactory))) {
            if (toXContent.isFragment()) {
                builder.startObject();
            }
            toXContent.toXContent(builder, params);
            if (toXContent.isFragment()) {
                builder.endObject();
            }

            Generator generator = (Generator) builder.generator();
            return generator.getTopLevelObject();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static Map<String, Object> toMap(ToXContent toXContent) {
        Object object = toObjectTree(toXContent);

        if (object instanceof Map) {
            HashMap<String, Object> result = new HashMap<>();

            for (Map.Entry<?, ?> entry : ((Map<?, ?>) object).entrySet()) {
                result.put(String.valueOf(entry.getKey()), entry.getValue());
            }

            return result;
        } else {
            return Collections.singletonMap("_value", object);
        }
    }

    private final Supplier<Map<?, ?>> mapFactory;

    public ObjectTreeXContent(Supplier<Map<?, ?>> mapFactory) {
        this.mapFactory = mapFactory;
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
        return new Generator(includes, excludes, this.mapFactory);
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
        private List<Object> objectStack = new ArrayList<>();
        private List<Object> topLevelObjects = new ArrayList<>();
        private String currentKey = null;
        private final Supplier<Map<?, ?>> mapFactory;

        Generator(Set<String> includes, Set<String> excludes, Supplier<Map<?, ?>> mapFactory) {
            this.includes = includes;
            this.excludes = excludes;
            this.mapFactory = mapFactory;
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
            Map<?, ?> map = mapFactory.get();

            this.objectStack.add(addObject(map));
        }

        @Override
        public void writeEndObject() throws IOException {
            pop();
        }

        @Override
        public void writeStartArray() throws IOException {
            List<Object> list = new ArrayList<Object>();

            this.objectStack.add(addObject(list));
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
            addObject(null);
        }

        @Override
        public void writeNullField(String name) throws IOException {
            addObject(name, null);
        }

        @Override
        public void writeBooleanField(String name, boolean value) throws IOException {
            addObject(name, value);
        }

        @Override
        public void writeBoolean(boolean value) throws IOException {
            addObject(value);
        }

        @Override
        public void writeNumberField(String name, double value) throws IOException {
            addObject(name, value);
        }

        @Override
        public void writeNumber(double value) throws IOException {
            addObject(value);
        }

        @Override
        public void writeNumberField(String name, float value) throws IOException {
            addObject(name, value);
        }

        @Override
        public void writeNumber(float value) throws IOException {
            addObject(value);
        }

        @Override
        public void writeNumberField(String name, int value) throws IOException {
            addObject(name, value);
        }

        @Override
        public void writeNumber(int value) throws IOException {
            addObject(value);
        }

        @Override
        public void writeNumberField(String name, long value) throws IOException {
            addObject(name, value);
        }

        @Override
        public void writeNumber(long value) throws IOException {
            addObject(value);
        }

        @Override
        public void writeNumber(short value) throws IOException {
            addObject(value);
        }

        @Override
        public void writeNumber(BigInteger value) throws IOException {
            addObject(value);
        }

        @Override
        public void writeNumberField(String name, BigInteger value) throws IOException {
            addObject(name, value);
        }

        @Override
        public void writeNumber(BigDecimal value) throws IOException {
            addObject(value);
        }

        @Override
        public void writeNumberField(String name, BigDecimal value) throws IOException {
            addObject(name, value);
        }

        @Override
        public void writeStringField(String name, String value) throws IOException {
            addObject(name, value);
        }

        @Override
        public void writeString(String value) throws IOException {
            addObject(value);
        }

        @Override
        public void writeString(char[] text, int offset, int len) throws IOException {
            addObject(new String(text, offset, len));
        }

        @Override
        public void writeUTF8String(byte[] value, int offset, int length) throws IOException {
            addObject(new String(value, offset, length, "UTF-8"));
        }

        @Override
        public void writeBinaryField(String name, byte[] value) throws IOException {
            addObject(name, value);
        }

        @Override
        public void writeBinary(byte[] value) throws IOException {
            addObject(value);
        }

        @Override
        public void writeBinary(byte[] value, int offset, int length) throws IOException {
            byte[] valueSection = new byte[length];
            System.arraycopy(value, offset, valueSection, 0, length);
            addObject(value);
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

        Object getTopLevelObject() {
            if (topLevelObjects.size() == 0) {
                return null;
            } else if (topLevelObjects.size() > 1) {
                log.warn("More than one top level object was produced. Using first one: " + this.topLevelObjects);
            }

            return this.topLevelObjects.get(0);
        }

        @SuppressWarnings("unchecked")
        private Object addObject(Object key, Object object) throws IOException {
            Object top = top();

            if (top == null) {
                this.topLevelObjects.add(object);
            } else if (top instanceof Collection) {
                ((Collection<Object>) top).add(object);
            } else if (top instanceof Map) {
                String keyString = String.valueOf(key);
                ((Map<Object, Object>) top).put(keyString, object);
                object = ((Map<Object, Object>) top).get(keyString);
            } else {
                throw new IOException("Invalid object structure: " + top + " is not a container.");
            }

            return object;
        }

        private Object addObject(Object object) throws IOException {
            object = addObject(this.currentKey, object);
            this.currentKey = null;
            return object;
        }

        private Object top() {
            if (this.objectStack.size() == 0) {
                return null;
            } else {
                return this.objectStack.get(this.objectStack.size() - 1);
            }
        }

        private Object pop() {
            if (this.objectStack.size() == 0) {
                return null;
            } else {
                return this.objectStack.remove(this.objectStack.size() - 1);
            }
        }

    }
}

