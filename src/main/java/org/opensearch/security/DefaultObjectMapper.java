/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableSet;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.InjectableValues;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import com.fasterxml.jackson.databind.introspect.BeanPropertyDefinition;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import org.opensearch.SpecialPermission;

class ConfigMapSerializer extends StdSerializer<Map<String, Object>> {
    private static final Set<String> SENSITIVE_CONFIG_KEYS = Set.of("password");

    @SuppressWarnings("unchecked")
    public ConfigMapSerializer() {
        // Pass Map<String, Object>.class to the superclass
        super((Class<Map<String, Object>>) (Class<?>) Map.class);
    }

    @Override
    public void serialize(Map<String, Object> value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
        gen.writeStartObject();
        for (Map.Entry<String, Object> entry : value.entrySet()) {
            if (SENSITIVE_CONFIG_KEYS.contains(entry.getKey())) {
                gen.writeStringField(entry.getKey(), "******"); // Redact
            } else {
                gen.writeObjectField(entry.getKey(), entry.getValue());
            }
        }
        gen.writeEndObject();
    }
}

public class DefaultObjectMapper {
    public static final ObjectMapper objectMapper = new ObjectMapper();
    public final static ObjectMapper YAML_MAPPER = new ObjectMapper(new YAMLFactory());
    private static final ObjectMapper defaulOmittingObjectMapper = new ObjectMapper();

    static {
        objectMapper.setSerializationInclusion(Include.NON_NULL);
        // exclude sensitive information from the request body,
        // if jackson cant parse the entity, e.g. passwords, hashes and so on,
        // but provides which property is unknown
        objectMapper.disable(JsonParser.Feature.INCLUDE_SOURCE_IN_LOCATION);
        defaulOmittingObjectMapper.disable(JsonParser.Feature.INCLUDE_SOURCE_IN_LOCATION);
        YAML_MAPPER.disable(JsonParser.Feature.INCLUDE_SOURCE_IN_LOCATION);
        // objectMapper.enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
        objectMapper.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
        defaulOmittingObjectMapper.setSerializationInclusion(Include.NON_DEFAULT);
        defaulOmittingObjectMapper.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
        YAML_MAPPER.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    }

    private DefaultObjectMapper() {}

    public static void inject(final InjectableValues.Std injectableValues) {
        objectMapper.setInjectableValues(injectableValues);
        YAML_MAPPER.setInjectableValues(injectableValues);
        defaulOmittingObjectMapper.setInjectableValues(injectableValues);
    }

    public static boolean getOrDefault(Map<String, Object> properties, String key, boolean defaultValue) throws JsonProcessingException {
        Object value = properties.get(key);
        if (value == null) {
            return defaultValue;
        } else if (value instanceof Boolean) {
            return (boolean) value;
        } else if (value instanceof String) {
            String text = ((String) value).trim();
            if ("true".equals(text) || "True".equals(text)) {
                return true;
            }
            if ("false".equals(text) || "False".equals(text)) {
                return false;
            }
            throw InvalidFormatException.from(
                null,
                "Cannot deserialize value of type 'boolean' from String \"" + text + "\": only \"true\" or \"false\" recognized)",
                null,
                Boolean.class
            );
        }
        throw MismatchedInputException.from(
            null,
            Boolean.class,
            "Cannot deserialize instance of 'boolean' out of '" + value + "' (Property: " + key + ")"
        );
    }

    @SuppressWarnings("unchecked")
    public static <T> T getOrDefault(Map<String, Object> properties, String key, T defaultValue) {
        T value = (T) properties.get(key);
        return value != null ? value : defaultValue;
    }

    public static <T> T readTree(JsonNode node, Class<T> clazz) throws IOException {

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            return AccessController.doPrivileged((PrivilegedExceptionAction<T>) () -> objectMapper.treeToValue(node, clazz));
        } catch (final PrivilegedActionException e) {
            throw (IOException) e.getCause();
        }
    }

    @SuppressWarnings("removal")
    public static <T> T readValue(String string, Class<T> clazz) throws IOException {

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            return AccessController.doPrivileged((PrivilegedExceptionAction<T>) () -> objectMapper.readValue(string, clazz));
        } catch (final PrivilegedActionException e) {
            throw (IOException) e.getCause();
        }
    }

    @SuppressWarnings("removal")
    public static JsonNode readTree(String string) throws IOException {

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            return AccessController.doPrivileged((PrivilegedExceptionAction<JsonNode>) () -> objectMapper.readTree(string));
        } catch (final PrivilegedActionException e) {
            throw (IOException) e.getCause();
        }
    }

    @SuppressWarnings("removal")
    public static String writeValueAsString(Object value, boolean omitDefaults) throws JsonProcessingException {

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            return AccessController.doPrivileged(
                (PrivilegedExceptionAction<String>) () -> (omitDefaults ? defaulOmittingObjectMapper : objectMapper).writeValueAsString(
                    value
                )
            );
        } catch (final PrivilegedActionException e) {
            throw (JsonProcessingException) e.getCause();
        }

    }

    @SuppressWarnings("removal")
    public static String writeValueAsStringAndRedactSensitive(Object value) throws JsonProcessingException {
        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        SimpleModule module = new SimpleModule();
        module.addSerializer(new ConfigMapSerializer());
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(module);

        try {
            return AccessController.doPrivileged((PrivilegedExceptionAction<String>) () -> mapper.writeValueAsString(value));
        } catch (final PrivilegedActionException e) {
            throw (JsonProcessingException) e.getCause();
        }

    }

    @SuppressWarnings("removal")
    public static <T> T readValue(String string, TypeReference<T> tr) throws IOException {

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<T>() {
                @Override
                public T run() throws Exception {
                    return objectMapper.readValue(string, tr);
                }
            });
        } catch (final PrivilegedActionException e) {
            throw (IOException) e.getCause();
        }

    }

    @SuppressWarnings("removal")
    public static <T> T readValue(String string, JavaType jt) throws IOException {

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            return AccessController.doPrivileged((PrivilegedExceptionAction<T>) () -> objectMapper.readValue(string, jt));
        } catch (final PrivilegedActionException e) {
            throw (IOException) e.getCause();
        }
    }

    public static TypeFactory getTypeFactory() {
        return objectMapper.getTypeFactory();
    }

    public static Set<String> getFields(Class<?> cls) {
        return objectMapper.getSerializationConfig()
            .introspect(getTypeFactory().constructType(cls))
            .findProperties()
            .stream()
            .map(BeanPropertyDefinition::getName)
            .collect(ImmutableSet.toImmutableSet());
    }
}
