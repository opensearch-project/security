/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework;

import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.google.common.collect.ImmutableMap.Builder;

import static org.apache.commons.lang3.StringUtils.isNoneBlank;

public class JwtConfigBuilder {
    private String jwtHeader;
    private String jwtUrlParameter;
    private List<String> signingKeys;
    private List<String> subjectKey;
    private List<String> rolesKey;

    public JwtConfigBuilder jwtHeader(String jwtHeader) {
        this.jwtHeader = jwtHeader;
        return this;
    }

    public JwtConfigBuilder jwtUrlParameter(String jwtUrlParameter) {
        this.jwtUrlParameter = jwtUrlParameter;
        return this;
    }

    public JwtConfigBuilder signingKey(List<String> signingKeys) {
        this.signingKeys = signingKeys;
        return this;
    }

    public JwtConfigBuilder subjectKey(String subjectKey) {
        this.subjectKey = List.of(subjectKey);
        return this;
    }

    public JwtConfigBuilder subjectKey(List<String> subjectKey) {
        this.subjectKey = subjectKey;
        return this;
    }

    public JwtConfigBuilder rolesKey(String rolesKey) {
        this.rolesKey = List.of(rolesKey);
        return this;
    }

    public JwtConfigBuilder rolesKey(List<String> rolesKey) {
        this.rolesKey = rolesKey;
        return this;
    }

    public Map<String, Object> build() {
        Builder<String, Object> builder = new Builder<>();
        if (Objects.isNull(signingKeys)) {
            throw new IllegalStateException("Signing key is required.");
        }
        builder.put("signing_key", signingKeys);
        if (isNoneBlank(jwtHeader)) {
            builder.put("jwt_header", jwtHeader);
        }
        if (isNoneBlank(jwtUrlParameter)) {
            builder.put("jwt_url_parameter", jwtUrlParameter);
        }
        if (subjectKey != null && !subjectKey.isEmpty()) {
            builder.put("subject_key", subjectKey);
        }
        if (rolesKey != null && !rolesKey.isEmpty()) {
            builder.put("roles_key", rolesKey);
        }
        return builder.build();
    }
}
