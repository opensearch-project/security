/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazon.opendistroforelasticsearch.security.dlic.rest.validation;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.auditlog.config.AuditConfig;
import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory;
import com.google.common.collect.ImmutableSet;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestRequest;

import java.util.Set;

public class AuditValidator extends AbstractConfigurationValidator {

    private static final Set<AuditCategory> DISABLED_REST_CATEGORIES = ImmutableSet.of(
            AuditCategory.BAD_HEADERS,
            AuditCategory.SSL_EXCEPTION,
            AuditCategory.AUTHENTICATED,
            AuditCategory.FAILED_LOGIN,
            AuditCategory.GRANTED_PRIVILEGES,
            AuditCategory.MISSING_PRIVILEGES
    );

    private static final Set<AuditCategory> DISABLED_TRANSPORT_CATEGORIES = ImmutableSet.of(
            AuditCategory.BAD_HEADERS,
            AuditCategory.SSL_EXCEPTION,
            AuditCategory.AUTHENTICATED,
            AuditCategory.FAILED_LOGIN,
            AuditCategory.GRANTED_PRIVILEGES,
            AuditCategory.MISSING_PRIVILEGES,
            AuditCategory.INDEX_EVENT,
            AuditCategory.OPENDISTRO_SECURITY_INDEX_ATTEMPT
    );

    public AuditValidator(final RestRequest request,
                          final BytesReference ref,
                          final Settings opensearchSettings,
                          final Object... param) {
        super(request, ref, opensearchSettings, param);
        this.payloadMandatory = true;
        this.allowedKeys.put("enabled", DataType.BOOLEAN);
        this.allowedKeys.put("audit", DataType.OBJECT);
        this.allowedKeys.put("compliance", DataType.OBJECT);
    }

    @Override
    public boolean validate() {
        if (!super.validate()) {
            return false;
        }

        if ((request.method() == RestRequest.Method.PUT || request.method() == RestRequest.Method.PATCH)
                && this.content != null
                && this.content.length() > 0) {
            try {
                // try parsing to target type
                final AuditConfig auditConfig = DefaultObjectMapper.readTree(getContentAsNode(), AuditConfig.class);
                final AuditConfig.Filter filter = auditConfig.getFilter();
                if (!DISABLED_REST_CATEGORIES.containsAll(filter.getDisabledRestCategories())) {
                    throw new IllegalArgumentException("Invalid REST categories passed in the request");
                }
                if (!DISABLED_TRANSPORT_CATEGORIES.containsAll(filter.getDisabledTransportCategories())) {
                    throw new IllegalArgumentException("Invalid transport categories passed in the request");
                }
            } catch (Exception e) {
                // this.content is not valid json
                this.errorType = ErrorType.BODY_NOT_PARSEABLE;
                log.error("Invalid content passed in the request", e);
                return false;
            }
        }
        return true;
    }
}
