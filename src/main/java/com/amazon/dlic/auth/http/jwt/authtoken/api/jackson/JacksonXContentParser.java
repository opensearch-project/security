package com.amazon.dlic.auth.http.jwt.authtoken.api.jackson;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.LinkedList;

import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.xcontent.DeprecationHandler;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class JacksonXContentParser {

    public static JsonNode readTree(BytesReference data, XContentType contentType) throws IOException {
        return readTree(BytesReference.toBytes(data), contentType);
    }

    public static JsonNode readTree(byte[] data, XContentType contentType) throws IOException {
        return new JacksonXContentParser(data, contentType).readTree();
    }

    private XContentParser parser;
    private LinkedList<JsonNode> nodeStack = new LinkedList<>();
    private JsonNode currentNode;
    private JsonNode topNode;
    private String currentAttributeName = null;
    private JsonNodeFactory nodeFactory = JsonNodeFactory.instance;

    public JacksonXContentParser(byte[] data, XContentType contentType) throws IOException {
        parser = contentType.xContent().createParser(NamedXContentRegistry.EMPTY, DeprecationHandler.IGNORE_DEPRECATIONS, data);
    }

    public JsonNode readTree() throws IOException {

        for (XContentParser.Token token = parser.currentToken() != null ? parser.currentToken() : parser.nextToken(); token != null; token = parser
                .nextToken()) {

            switch (token) {
                case START_OBJECT:
                    if (currentNode != null) {
                        nodeStack.add(currentNode);
                    }
                    currentNode = addNode(nodeFactory.objectNode());
                    break;

                case START_ARRAY:
                    if (currentNode != null) {
                        nodeStack.add(currentNode);
                    }

                    currentNode = addNode(nodeFactory.arrayNode());
                    break;

                case END_OBJECT:
                case END_ARRAY:
                    if (!nodeStack.isEmpty()) {
                        currentNode = nodeStack.removeLast();
                    } else {
                        currentNode = null;
                    }
                    break;

                case FIELD_NAME:
                    currentAttributeName = parser.currentName();
                    break;

                case VALUE_BOOLEAN:
                    addNode(nodeFactory.booleanNode(parser.booleanValue()));
                    break;

                case VALUE_EMBEDDED_OBJECT:
                    throw new IOException("VALUE_EMBEDDED_OBJECT is not supported: " + parser);

                case VALUE_NULL:
                    addNode(nodeFactory.nullNode());
                    break;

                case VALUE_NUMBER:
                    switch (parser.numberType()) {
                        case BIG_DECIMAL:
                            addNode(nodeFactory.numberNode(new BigDecimal(parser.numberValue().toString())));
                            break;
                        case BIG_INTEGER:
                            addNode(nodeFactory.numberNode(new BigInteger(parser.numberValue().toString())));
                            break;
                        case DOUBLE:
                            addNode(nodeFactory.numberNode(parser.doubleValue()));
                            break;
                        case FLOAT:
                            addNode(nodeFactory.numberNode(parser.floatValue()));
                            break;
                        case INT:
                            addNode(nodeFactory.numberNode(parser.intValue()));
                            break;
                        case LONG:
                            addNode(nodeFactory.numberNode(parser.longValue()));
                            break;
                    }
                    break;
                case VALUE_STRING:
                    addNode(nodeFactory.textNode(parser.text()));
                    break;
            }

            if (topNode == null) {
                topNode = currentNode;
            }
        }

        return topNode;
    }

    private JsonNode addNode(JsonNode newNode) throws IOException {
        if (currentNode instanceof ArrayNode) {
            ((ArrayNode) currentNode).add(newNode);
        } else if (currentNode instanceof ObjectNode) {
            if (currentAttributeName == null) {
                throw new IOException("Missing attribute name at " + parser.getTokenLocation());
            }

            ((ObjectNode) currentNode).set(currentAttributeName, newNode);
        } else if (currentNode != null) {
            throw new IOException("Object node in wrong context " + parser.getTokenLocation());
        }

        currentAttributeName = null;

        return newNode;
    }

}

