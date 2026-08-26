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

import com.fasterxml.jackson.annotation.JsonInclude;

import org.opensearch.secure_sm.AccessController;

import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.InjectableValues;
import tools.jackson.databind.JavaType;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.introspect.DefaultAccessorNamingStrategy;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.type.TypeFactory;

public class NonValidatingObjectMapper {
    private static volatile ObjectMapper nonValidatingObjectMapper;

    static {
        nonValidatingObjectMapper = JsonMapper.builder()
            .accessorNaming(new DefaultAccessorNamingStrategy.Provider().withFirstCharAcceptance(true, true))
            .disable(StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION)
            .changeDefaultPropertyInclusion(incl -> incl.withValueInclusion(JsonInclude.Include.NON_NULL))
            .changeDefaultPropertyInclusion(incl -> incl.withContentInclusion(JsonInclude.Include.NON_NULL))
            .configure(StreamReadFeature.STRICT_DUPLICATE_DETECTION, false)
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .configure(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES, false)
            .configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, false)
            .configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, false)
            .build();
    }

    public static void inject(final InjectableValues.Std injectableValues) {
        nonValidatingObjectMapper = nonValidatingObjectMapper.rebuild().injectableValues(injectableValues).build();
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
