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
    private final boolean isInternal;
    private final String authDomain;

    @ConstructorProperties({ "custom_attribute_names", "user_is_internal", "user_auth_domain" })
    public AuthInfo(List<String> customAttributeNames, boolean isInternal, String authDomain) {
        this.customAttributeNames = customAttributeNames;
        this.isInternal = isInternal;
        this.authDomain = authDomain;
    }

    public List<String> getCustomAttributeNames() {
        return customAttributeNames;
    }

    public boolean isInternal() {
        return isInternal;
    }

    public String getAuthDomain() {
        return authDomain;
    }
}
