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

import java.util.Map;
import java.util.Objects;

import com.google.common.collect.ImmutableMap.Builder;

import static org.apache.commons.lang3.StringUtils.isNoneBlank;

public class JwtConfigBuilder {
    private String jwtHeader;
    private String jwtUrlParameter;
    private String signingKey;
    private String subjectKey;
    private String rolesKey;

    public JwtConfigBuilder jwtHeader(String jwtHeader) {
        this.jwtHeader = jwtHeader;
        return this;
    }

    public JwtConfigBuilder jwtUrlParameter(String jwtUrlParameter) {
        this.jwtUrlParameter = jwtUrlParameter;
        return this;
    }

    public JwtConfigBuilder signingKey(String signingKey) {
        this.signingKey = signingKey;
        return this;
    }

    public JwtConfigBuilder subjectKey(String subjectKey) {
        this.subjectKey = subjectKey;
        return this;
    }

    public JwtConfigBuilder rolesKey(String rolesKey) {
        this.rolesKey = rolesKey;
        return this;
    }

    public Map<String, Object> build() {
        Builder<String, Object> builder = new Builder<>();
        if (Objects.isNull(signingKey)) {
            throw new IllegalStateException("Signing key is required.");
        }
        builder.put("signing_key", signingKey);
        if (isNoneBlank(jwtHeader)) {
            builder.put("jwt_header", jwtHeader);
        }
        if (isNoneBlank(jwtUrlParameter)) {
            builder.put("jwt_url_parameter", jwtUrlParameter);
        }
        if (isNoneBlank(subjectKey)) {
            builder.put("subject_key", subjectKey);
        }
        if (isNoneBlank(rolesKey)) {
            builder.put("roles_key", rolesKey);
        }
        return builder.build();
    }
}
