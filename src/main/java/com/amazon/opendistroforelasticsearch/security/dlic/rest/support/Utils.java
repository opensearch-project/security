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

package com.amazon.opendistroforelasticsearch.security.dlic.rest.support;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.Map;

import org.elasticsearch.ElasticsearchParseException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.common.xcontent.json.JsonXContent;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.support.OpenDistroSecurityDeprecationHandler;

public class Utils {

    private static final ObjectMapper internalMapper = new ObjectMapper();

    public static Map<String, Object> convertJsonToxToStructuredMap(ToXContent jsonContent) {
        Map<String, Object> map = null;
        try {
            final BytesReference bytes = XContentHelper.toXContent(jsonContent, XContentType.JSON, false);
            map = XContentHelper.convertToMap(bytes, false, XContentType.JSON).v2();
        } catch (IOException e1) {
            throw ExceptionsHelper.convertToElastic(e1);
        }

        return map;
    }

    public static Map<String, Object> convertJsonToxToStructuredMap(String jsonContent) {
        try (XContentParser parser = XContentType.JSON.xContent().createParser(NamedXContentRegistry.EMPTY, OpenDistroSecurityDeprecationHandler.INSTANCE, jsonContent)) {
            return parser.map();
        } catch (IOException e1) {
            throw ExceptionsHelper.convertToElastic(e1);
        }
    }

    public static BytesReference convertStructuredMapToBytes(Map<String, Object> structuredMap) {
        try {
            return BytesReference.bytes(JsonXContent.contentBuilder().map(structuredMap));
        } catch (IOException e) {
            throw new ElasticsearchParseException("Failed to convert map", e);
        }
    }

    public static String convertStructuredMapToJson(Map<String, Object> structuredMap) {
        try {
            return XContentHelper.convertToJson(convertStructuredMapToBytes(structuredMap), false, XContentType.JSON);
        } catch (IOException e) {
            throw new ElasticsearchParseException("Failed to convert map", e);
        }
    }

    public static JsonNode convertJsonToJackson(BytesReference jsonContent) {
        try {
            return DefaultObjectMapper.readTree(jsonContent.utf8ToString());
        } catch (IOException e1) {
            throw ExceptionsHelper.convertToElastic(e1);
        }

    }

    public static JsonNode convertJsonToJackson(ToXContent jsonContent, boolean omitDefaults) {
        try {
            Map<String, String> pm = new HashMap<>(1);
            pm.put("omit_defaults", String.valueOf(omitDefaults));
            ToXContent.MapParams params = new ToXContent.MapParams(pm);

            final BytesReference bytes = XContentHelper.toXContent(jsonContent, XContentType.JSON, params, false);
            return DefaultObjectMapper.readTree(bytes.utf8ToString());
        } catch (IOException e1) {
            throw ExceptionsHelper.convertToElastic(e1);
        }

    }

    public static <T> T serializeToXContentToPojo(ToXContent jsonContent, Class<T> clazz) {
        try {

            if (jsonContent instanceof BytesReference) {
                return serializeToXContentToPojo(((BytesReference) jsonContent).utf8ToString(), clazz);
            }

            final BytesReference bytes = XContentHelper.toXContent(jsonContent, XContentType.JSON, false);
            return DefaultObjectMapper.readValue(bytes.utf8ToString(), clazz);
        } catch (IOException e1) {
            throw ExceptionsHelper.convertToElastic(e1);
        }

    }

    public static <T> T serializeToXContentToPojo(String jsonContent, Class<T> clazz) {
        try {
            return DefaultObjectMapper.readValue(jsonContent, clazz);
        } catch (IOException e1) {
            throw ExceptionsHelper.convertToElastic(e1);
        }

    }

    public static byte[] jsonMapToByteArray(Map<String, Object> jsonAsMap) throws IOException {

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<byte[]>() {
                @Override
                public byte[] run() throws Exception {
                    return internalMapper.writeValueAsBytes(jsonAsMap);
                }
            });
        } catch (final PrivilegedActionException e) {
            if (e.getCause() instanceof JsonProcessingException) {
                throw (JsonProcessingException) e.getCause();
            } else if (e.getCause() instanceof RuntimeException) {
                throw (RuntimeException) e.getCause();
            } else {
                throw new RuntimeException(e.getCause());
            }
        }
    }

    public static Map<String, Object> byteArrayToMutableJsonMap(byte[] jsonBytes) throws IOException {

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<Map<String, Object>>() {
                @Override
                public Map<String, Object> run() throws Exception {
                    return internalMapper.readValue(jsonBytes, new TypeReference<Map<String, Object>>() {});
                }
            });
        } catch (final PrivilegedActionException e) {
            if (e.getCause() instanceof IOException) {
                throw (IOException) e.getCause();
            } else if (e.getCause() instanceof RuntimeException) {
                throw (RuntimeException) e.getCause();
            } else {
                throw new RuntimeException(e.getCause());
            }
        }
    }
}
