package com.amazon.opendistroforelasticsearch.security.json;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;

public class BasicJsonReader {

    public static Object read(JsonParser parser) throws JsonProcessingException, IOException {
        return new BasicJsonReader(parser).read();
    }

    public static Object read(InputStream in) throws JsonProcessingException, IOException {
        try (JsonParser parser = jsonFactory.createParser(in)) {
            return new BasicJsonReader(parser).read();
        }
    }

    public static Object read(String string) throws JsonProcessingException {
        try (JsonParser parser = jsonFactory.createParser(string)) {
            return new BasicJsonReader(parser).read();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static Map<String, Object> readObject(InputStream in) throws JsonProcessingException, IOException {
        Object parsedDocument = read(in);

        if (parsedDocument instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> result = (Map<String, Object>) parsedDocument;

            return result;
        } else {
            throw new UnexpectedJsonStructureException(
                    "Expected a JSON object. Got: " + (parsedDocument instanceof List ? "Array" : String.valueOf(parsedDocument)));
        }
    }

    public static Map<String, Object> readObject(String string) throws JsonProcessingException, IOException {
        Object parsedDocument = read(string);

        if (parsedDocument instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> result = (Map<String, Object>) parsedDocument;

            return result;
        } else {
            throw new UnexpectedJsonStructureException(
                    "Expected a JSON object. Got: " + (parsedDocument instanceof List ? "Array" : String.valueOf(parsedDocument)));
        }
    }

    private static JsonFactory jsonFactory = new JsonFactory();

    private JsonParser parser;
    private LinkedList<Object> nodeStack = new LinkedList<>();
    private Object currentNode;
    private Object topNode;
    private String currentAttributeName = null;

    public BasicJsonReader(JsonParser parser) {
        this.parser = parser;
    }

    public Object read() throws IOException, JsonProcessingException {

        for (JsonToken token = parser.currentToken() != null ? parser.currentToken() : parser.nextToken(); token != null; token = parser
                .nextToken()) {

            switch (token) {

                case START_OBJECT:
                    if (currentNode != null) {
                        nodeStack.add(currentNode);
                    }

                    currentNode = addNode(new LinkedHashMap<String, Object>());
                    break;

                case START_ARRAY:
                    if (currentNode != null) {
                        nodeStack.add(currentNode);
                    }

                    currentNode = addNode(new ArrayList<Object>());
                    break;

                case END_OBJECT:
                case END_ARRAY:
                    if (nodeStack.isEmpty()) {
                        currentNode = null;
                    } else {
                        currentNode = nodeStack.removeLast();
                    }
                    break;

                case FIELD_NAME:
                    currentAttributeName = parser.currentName();
                    break;

                case VALUE_TRUE:
                    addNode(Boolean.TRUE);
                    break;

                case VALUE_FALSE:
                    addNode(Boolean.FALSE);
                    break;

                case VALUE_NULL:
                    addNode(null);
                    break;

                case VALUE_NUMBER_FLOAT:
                case VALUE_NUMBER_INT:
                    addNode(parser.getNumberValue());
                    break;

                case VALUE_STRING:
                    addNode(parser.getText());
                    break;

                case VALUE_EMBEDDED_OBJECT:
                    addNode(parser.getEmbeddedObject());
                    break;

                default:
                    throw new JsonParseException(parser, "Unexpected token: " + token);

            }

            if (nodeStack.isEmpty() && currentNode == null) {
                break;
            }
        }

        parser.clearCurrentToken();

        return topNode;
    }

    private Object addNode(Object newNode) throws JsonProcessingException {
        if (topNode == null) {
            topNode = newNode;
        }

        if (currentNode instanceof Collection) {
            @SuppressWarnings("unchecked")
            Collection<Object> collection = (Collection<Object>) currentNode;

            collection.add(newNode);
        } else if (currentNode instanceof Map) {
            if (currentAttributeName == null) {
                throw new JsonParseException(parser, "Missing attribute name");
            }

            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) currentNode;

            map.put(currentAttributeName, newNode);
        } else if (currentNode != null) {
            throw new JsonParseException(parser, "Node in wrong context");
        }

        currentAttributeName = null;

        return newNode;
    }
}
