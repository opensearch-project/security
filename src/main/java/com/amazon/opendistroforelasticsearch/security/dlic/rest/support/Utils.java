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
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.elasticsearch.ElasticsearchParseException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.common.xcontent.json.JsonXContent;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.support.OpenDistroSecurityDeprecationHandler;
import com.fasterxml.jackson.databind.JsonNode;

public class Utils {

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

    public static JsonNode convertJsonToJackson(ToXContent jsonContent) {
        try {
            final BytesReference bytes = XContentHelper.toXContent(jsonContent, XContentType.JSON, false);
            return DefaultObjectMapper.objectMapper.readTree(bytes.utf8ToString());
        } catch (IOException e1) {
            throw ExceptionsHelper.convertToElastic(e1);
        }

    }

    /**
     * This generates hash for a given password
     * @param clearTextPassword plain text password for which hash should be generated.
     *                          This will be cleared from memory.
     * @return hash of the password
     */
    public static String hash(final char[] clearTextPassword) {
        final byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        final String hash = OpenBSDBCrypt.generate((Objects.requireNonNull(clearTextPassword)), salt, 12);
        Arrays.fill(salt, (byte) 0);
        Arrays.fill(clearTextPassword, '\0');
        return hash;
    }
}
