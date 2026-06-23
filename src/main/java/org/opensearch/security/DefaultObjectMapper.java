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
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableSet;
import com.fasterxml.jackson.annotation.JsonInclude;

import org.opensearch.secure_sm.AccessController;

import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonGenerator;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.InjectableValues;
import tools.jackson.databind.JavaType;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.exc.InvalidFormatException;
import tools.jackson.databind.exc.MismatchedInputException;
import tools.jackson.databind.introspect.AnnotatedClass;
import tools.jackson.databind.introspect.BeanPropertyDefinition;
import tools.jackson.databind.introspect.ClassIntrospector;
import tools.jackson.databind.introspect.DefaultAccessorNamingStrategy;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.module.SimpleModule;
import tools.jackson.databind.ser.std.StdSerializer;
import tools.jackson.databind.type.TypeFactory;
import tools.jackson.dataformat.yaml.YAMLFactory;

class ConfigMapSerializer extends StdSerializer<Map<String, Object>> {
    private static final Set<String> SENSITIVE_CONFIG_KEYS = Set.of("password");

    @SuppressWarnings("unchecked")
    public ConfigMapSerializer() {
        // Pass Map<String, Object>.class to the superclass
        super((Class<Map<String, Object>>) (Class<?>) Map.class);
    }

    @Override
    public void serialize(Map<String, Object> value, JsonGenerator gen, SerializationContext serializers) {
        gen.writeStartObject();
        for (Map.Entry<String, Object> entry : value.entrySet()) {
            if (SENSITIVE_CONFIG_KEYS.contains(entry.getKey())) {
                gen.writeStringProperty(entry.getKey(), "******"); // Redact
            } else {
                gen.writeName(entry.getKey()).writePOJO(entry.getValue());
            }
        }
        gen.writeEndObject();
    }
}

public class DefaultObjectMapper {
    private static volatile ObjectMapper objectMapper;
    private static volatile ObjectMapper YAML_MAPPER;
    private static volatile ObjectMapper defaulOmittingObjectMapper;

    static {
        // exclude sensitive information from the request body,
        // if jackson cant parse the entity, e.g. passwords, hashes and so on,
        // but provides which property is unknown

        objectMapper = JsonMapper.builder()
            .accessorNaming(new DefaultAccessorNamingStrategy.Provider().withFirstCharAcceptance(true, true))
            .disable(StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION)
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .changeDefaultPropertyInclusion(incl -> incl.withValueInclusion(JsonInclude.Include.NON_NULL))
            .changeDefaultPropertyInclusion(incl -> incl.withContentInclusion(JsonInclude.Include.NON_NULL))
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
            .configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, false)
            .configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, false)
            .build();

        defaulOmittingObjectMapper = JsonMapper.builder()
            .accessorNaming(new DefaultAccessorNamingStrategy.Provider().withFirstCharAcceptance(true, true))
            .disable(StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION)
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .changeDefaultPropertyInclusion(incl -> incl.withValueInclusion(JsonInclude.Include.NON_DEFAULT))
            .changeDefaultPropertyInclusion(incl -> incl.withContentInclusion(JsonInclude.Include.NON_DEFAULT))
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
            .configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, false)
            .configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, false)
            .build();

        // Why not YAMLMapper? It causes classloading issues (it inherits from
        // ObjectMapper but comes from server's lib, whereas ObjectMapper comes from
        // security plugin dependencies).
        YAML_MAPPER = new ObjectMapper(
            YAMLFactory.builder()
                .disable(StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION)
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                .build()
        ).rebuild()
            .accessorNaming(new DefaultAccessorNamingStrategy.Provider().withFirstCharAcceptance(true, true))
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
            .configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, false)
            .configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, false)
            .build();
    }

    private DefaultObjectMapper() {}

    public static ObjectMapper objectMapper() {
        return objectMapper;
    }

    public static ObjectMapper yamlMapper() {
        return YAML_MAPPER;
    }

    public static void inject(final InjectableValues.Std injectableValues) {
        objectMapper = objectMapper.rebuild().injectableValues(injectableValues).build();
        YAML_MAPPER = YAML_MAPPER.rebuild().injectableValues(injectableValues).build();
        defaulOmittingObjectMapper = defaulOmittingObjectMapper.rebuild().injectableValues(injectableValues).build();
    }

    public static boolean getOrDefault(Map<String, Object> properties, String key, boolean defaultValue) {
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
        try {
            return AccessController.doPrivilegedChecked(() -> objectMapper.treeToValue(node, clazz));
        } catch (final Exception e) {
            throw new IOException((JacksonException) e);
        }
    }

    public static <T> T readValue(String string, Class<T> clazz) throws IOException {
        try {
            return AccessController.doPrivilegedChecked(() -> objectMapper.readValue(string, clazz));
        } catch (final Exception e) {
            throw new IOException((JacksonException) e);
        }
    }

    public static JsonNode readTree(String string) throws IOException {
        try {
            return AccessController.doPrivilegedChecked(() -> objectMapper.readTree(string));
        } catch (final Exception e) {
            throw new IOException((JacksonException) e);
        }
    }

    public static String writeValueAsString(Object value, boolean omitDefaults) {
        try {
            return AccessController.doPrivilegedChecked(
                () -> (omitDefaults ? defaulOmittingObjectMapper : objectMapper).writeValueAsString(value)
            );
        } catch (final Exception e) {
            throw (JacksonException) e;
        }

    }

    public static String writeValueAsStringAndRedactSensitive(Object value) {

        SimpleModule module = new SimpleModule();
        module.addSerializer(new ConfigMapSerializer());
        ObjectMapper mapper = JsonMapper.builder()
            .accessorNaming(new DefaultAccessorNamingStrategy.Provider().withFirstCharAcceptance(true, true))
            .addModule(module)
            .build();

        try {
            return AccessController.doPrivilegedChecked(() -> mapper.writeValueAsString(value));
        } catch (final Exception e) {
            throw (JacksonException) e;
        }

    }

    public static <T> T readValue(String string, TypeReference<T> tr) throws IOException {
        try {
            return AccessController.doPrivilegedChecked(() -> objectMapper.readValue(string, tr));
        } catch (final Exception e) {
            throw new IOException((JacksonException) e);
        }

    }

    public static <T> T readValue(String string, JavaType jt) throws IOException {

        try {
            return AccessController.doPrivilegedChecked(() -> objectMapper.readValue(string, jt));
        } catch (final Exception e) {
            throw new IOException((JacksonException) e);
        }
    }

    public static <T> T convertValue(JsonNode jsonNode, JavaType jt) throws IOException {
        try {
            return AccessController.doPrivilegedChecked(() -> objectMapper.convertValue(jsonNode, jt));
        } catch (final Exception e) {
            throw new IOException((JacksonException) e);
        }
    }

    public static TypeFactory getTypeFactory() {
        return objectMapper.getTypeFactory();
    }

    public static Set<String> getFields(Class<?> cls) {
        final ClassIntrospector introspector = objectMapper.serializationConfig().classIntrospectorInstance();
        final JavaType javaType = getTypeFactory().constructType(cls);
        final AnnotatedClass annotatedClass = introspector.introspectClassAnnotations(javaType);
        return introspector.introspectForSerialization(javaType, annotatedClass)
            .findProperties()
            .stream()
            .map(BeanPropertyDefinition::getName)
            .collect(ImmutableSet.toImmutableSet());
    }
}
