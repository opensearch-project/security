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

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.InjectableValues;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.TypeFactory;

import org.opensearch.secure_sm.AccessController;

public class NonValidatingObjectMapper {
    private static final ObjectMapper nonValidatingObjectMapper = new ObjectMapper();

    static {
        nonValidatingObjectMapper.disable(JsonParser.Feature.INCLUDE_SOURCE_IN_LOCATION);
        nonValidatingObjectMapper.setSerializationInclusion(Include.NON_NULL);
        nonValidatingObjectMapper.configure(JsonParser.Feature.STRICT_DUPLICATE_DETECTION, false);
        nonValidatingObjectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        nonValidatingObjectMapper.configure(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES, false);
    }

    public static void inject(final InjectableValues.Std injectableValues) {
        nonValidatingObjectMapper.setInjectableValues(injectableValues);
    }

    public static <T> T readValue(String string, JavaType jt) throws IOException {
        try {
            return AccessController.doPrivilegedChecked(() -> nonValidatingObjectMapper.readValue(string, jt));
        } catch (final Exception e) {
            throw (IOException) e;
        }
    }

    public static TypeFactory getTypeFactory() {
        return nonValidatingObjectMapper.getTypeFactory();
    }

}
