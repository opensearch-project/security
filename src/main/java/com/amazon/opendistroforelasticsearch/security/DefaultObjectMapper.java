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
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import org.elasticsearch.SpecialPermission;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

public class DefaultObjectMapper {
    public static final ObjectMapper objectMapper = new ObjectMapper();
    public static final ObjectMapper YAML_MAPPER = new ObjectMapper(new YAMLFactory());
    private static final ObjectMapper defaulOmittingObjectMapper = new ObjectMapper();

    static {
        objectMapper.setSerializationInclusion(Include.NON_NULL);
        //objectMapper.enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
        objectMapper.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
        defaulOmittingObjectMapper.setSerializationInclusion(Include.NON_DEFAULT);
        defaulOmittingObjectMapper.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
        YAML_MAPPER.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    }

    public static <T> T readTree(JsonNode node, Class<T> clazz) throws IOException {

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<T>() {
                @Override
                public T run() throws Exception {
                    return objectMapper.treeToValue(node, clazz);
                }
            });
        } catch (final PrivilegedActionException e) {
            throw (IOException) e.getCause();
        }
    }

    public static <T> T readValue(String string, Class<T> clazz) throws IOException {

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<T>() {
                @Override
                public T run() throws Exception {
                    return objectMapper.readValue(string, clazz);
                }
            });
        } catch (final PrivilegedActionException e) {
            throw (IOException) e.getCause();
        }
    }

    public static JsonNode readTree(String string) throws IOException {

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

    public static String writeValueAsString(Object value, boolean omitDefaults) throws JsonProcessingException {

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<String>() {
                @Override
                public String run() throws Exception {
                    return (omitDefaults ? defaulOmittingObjectMapper : objectMapper).writeValueAsString(value);
                }
            });
        } catch (final PrivilegedActionException e) {
            throw (JsonProcessingException) e.getCause();
        }

    }

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

    public static <T> T readValue(String string, JavaType jt) throws IOException {

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<T>() {
                @Override
                public T run() throws Exception {
                    return objectMapper.readValue(string, jt);
                }
            });
        } catch (final PrivilegedActionException e) {
            throw (IOException) e.getCause();
        }
    }

    public static TypeFactory getTypeFactory() {
        return objectMapper.getTypeFactory();
    }

}
