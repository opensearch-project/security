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
package org.opensearch.security.dlic.rest.validation;

import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestRequest;

public class MultiTenancyConfigValidator extends AbstractConfigurationValidator {

    public static final String DEFAULT_TENANT_JSON_PROPERTY = "default_tenant";
    public static final String PRIVATE_TENANT_ENABLED_JSON_PROPERTY = "private_tenant_enabled";
    public static final String MULTITENANCY_ENABLED_JSON_PROPERTY = "multitenancy_enabled";


    public MultiTenancyConfigValidator(RestRequest request, BytesReference ref, Settings opensearchSettings, Object... param) {
        super(request, ref, opensearchSettings, param);
        this.payloadMandatory = true;
        allowedKeys.put(DEFAULT_TENANT_JSON_PROPERTY, DataType.STRING);
        allowedKeys.put(PRIVATE_TENANT_ENABLED_JSON_PROPERTY, DataType.BOOLEAN);
        allowedKeys.put(MULTITENANCY_ENABLED_JSON_PROPERTY, DataType.BOOLEAN);
    }

}
