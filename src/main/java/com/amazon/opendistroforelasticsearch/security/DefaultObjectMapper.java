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

import java.util.Map;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.InjectableValues;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

public class DefaultObjectMapper {
    public static final ObjectMapper objectMapper = new ObjectMapper();
    public final static ObjectMapper YAML_MAPPER = new ObjectMapper(new YAMLFactory());

    static {
        YAML_MAPPER.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    }

    public static void inject(final InjectableValues.Std injectableValues) {
        objectMapper.setInjectableValues(injectableValues);
    }

    public static boolean getOrDefault(Map<String, Object> properties, String key, boolean defaultValue) {
        Boolean value = (Boolean)properties.get(key);
        return value != null ? value.booleanValue() : defaultValue;
    }

    public static <T> T getOrDefault(Map<String, Object> properties, String key, T defaultValue) {
        T value = (T)properties.get(key);
        return value != null ? value : defaultValue;
    }
}

