package com.amazon.dlic.auth.http.jwt.authtoken.api.validation;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import com.amazon.dlic.auth.http.jwt.authtoken.api.jackson.JacksonXContentParser;

import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.xcontent.XContentType;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;


public class ValidatingJsonParser {

    private static final ObjectMapper jsonMapper = new ObjectMapper();
    private static final ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());

    public static JsonNode readTree(String string) throws ConfigValidationException {
        try {
            return readTree0(string, jsonMapper);
        } catch (JsonParseException e) {
            throw new ConfigValidationException(new JsonValidationError(null, e));
        } catch (IOException e) {
            throw new ConfigValidationException(new ValidationError(null, "Error while parsing JSON document: " + e.getMessage(), null).cause(e));
        }
    }

    public static JsonNode readYamlTree(String string) throws ConfigValidationException {
        try {
            return readTree0(string, yamlMapper);
        } catch (JsonParseException e) {
            throw new ConfigValidationException(new JsonValidationError(null, e));
        } catch (IOException e) {
            throw new ConfigValidationException(new ValidationError(null, "Error while parsing YAML document: " + e.getMessage(), null).cause(e));
        }
    }

    public static JsonNode readTree(BytesReference data, XContentType contentType) throws ConfigValidationException {
        try {
            return JacksonXContentParser.readTree(data, contentType);
        } catch (JsonParseException e) {
            throw new ConfigValidationException(new JsonValidationError(null, e));
        } catch (IOException e) {
            throw new ConfigValidationException(new ValidationError(null, "Error while parsing JSON document: " + e.getMessage(), null).cause(e));
        }
    }

    public static ObjectNode readObject(String string) throws ConfigValidationException {
        JsonNode jsonNode = readTree(string);

        if (jsonNode instanceof ObjectNode) {
            return (ObjectNode) jsonNode;
        } else {
            throw new ConfigValidationException(new ValidationError(null, "The JSON root node must be an object"));
        }
    }

    private static JsonNode readTree0(String string, ObjectMapper objectMapper) throws IOException {

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<JsonNode>() {
                @Override
                public JsonNode run() throws Exception {
                    return objectMapper.readTree(string);
                }
            });
        } catch (final PrivilegedActionException e) {
            throw (IOException) e.getCause();
        }
    }

}

