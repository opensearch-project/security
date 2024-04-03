/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.security.http;

import java.beans.ConstructorProperties;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
class AuthInfo {

    private final List<String> customAttributeNames;

    @ConstructorProperties("custom_attribute_names")
    public AuthInfo(List<String> customAttributeNames) {
        this.customAttributeNames = customAttributeNames;
    }

    public List<String> getCustomAttributeNames() {
        return customAttributeNames;
    }
}
