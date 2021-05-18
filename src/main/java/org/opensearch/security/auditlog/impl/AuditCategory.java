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

package org.opensearch.security.auditlog.impl;

import org.opensearch.security.support.ConfigConstants;

import com.google.common.collect.ImmutableSet;
import org.opensearch.common.settings.Settings;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

public enum AuditCategory {
    BAD_HEADERS,
    FAILED_LOGIN,
    MISSING_PRIVILEGES,
    GRANTED_PRIVILEGES,
    OPENDISTRO_SECURITY_INDEX_ATTEMPT,
    SSL_EXCEPTION,
    AUTHENTICATED,
    INDEX_EVENT,
    COMPLIANCE_DOC_READ,
    COMPLIANCE_DOC_WRITE,
    COMPLIANCE_EXTERNAL_CONFIG,
    COMPLIANCE_INTERNAL_CONFIG_READ,
    COMPLIANCE_INTERNAL_CONFIG_WRITE;

    public static Set<AuditCategory> parse(final Collection<String> categories) {
        if (categories.isEmpty())
            return Collections.emptySet();

        return categories
                .stream()
                .map(String::toUpperCase)
                .map(AuditCategory::valueOf)
                .collect(ImmutableSet.toImmutableSet());
    }

    public static Set<AuditCategory> from(final Settings settings, final String key) {
        return parse(ConfigConstants.getSettingAsSet(settings, key, ConfigConstants.OPENDISTRO_SECURITY_AUDIT_DISABLED_CATEGORIES_DEFAULT, true));
    }
}
