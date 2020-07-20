/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security;

import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.databind.introspect.BeanPropertyDefinition;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.google.common.collect.ImmutableSet;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.InjectableValues;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.elasticsearch.SpecialPermission;

public class DefaultObjectMapper {
    public static final ObjectMapper objectMapper = new ObjectMapper();
    public final static ObjectMapper YAML_MAPPER = new ObjectMapper(new YAMLFactory());

    static {
        YAML_MAPPER.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    }

    public static void inject(final InjectableValues.Std injectableValues) {
        objectMapper.setInjectableValues(injectableValues);
    }

    public static boolean getOrDefault(Map<String, Object> properties, String key, boolean defaultValue) throws JsonProcessingException {
        Object value = properties.get(key);
        if (value == null) {
            return defaultValue;
        } else if (value instanceof Boolean) {
            return (boolean)value;
        } else if (value instanceof String) {
            String text = ((String)value).trim();
            if ("true".equals(text) || "True".equals(text)) {
                return true;
            }
            if ("false".equals(text) || "False".equals(text)) {
                return false;
            }
            throw InvalidFormatException.from(null,
                    "Cannot deserialize value of type 'boolean' from String \"" + text + "\": only \"true\" or \"false\" recognized)",
                    null, Boolean.class);
        }
        throw MismatchedInputException.from(null, Boolean.class, "Cannot deserialize instance of 'boolean' out of '" + value + "' (Property: " + key + ")");
    }

    public static <T> T getOrDefault(Map<String, Object> properties, String key, T defaultValue) {
        T value = (T)properties.get(key);
        return value != null ? value : defaultValue;
    }

    public static String writeValueAsString(Object value) throws JsonProcessingException {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }
        try {
            return AccessController.doPrivileged((PrivilegedExceptionAction<String>) () -> objectMapper.writeValueAsString(value));
        } catch (final PrivilegedActionException e) {
            throw (JsonProcessingException) e.getCause();
        }
    }

    public static TypeFactory getTypeFactory() {
        return objectMapper.getTypeFactory();
    }

    public static Set<String> getFields(Class cls) {
        return objectMapper
                .getSerializationConfig()
                .introspect(getTypeFactory().constructType(cls))
                .findProperties()
                .stream()
                .map(BeanPropertyDefinition::getName)
                .collect(ImmutableSet.toImmutableSet());
    }
}

