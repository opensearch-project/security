package org.opensearch.security.dlic.rest.validation;

import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestRequest;

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

public class TenancyConfigValidator extends AbstractConfigurationValidator {

    public TenancyConfigValidator(final RestRequest request, final BytesReference ref, final Settings opensearchSettings, Object... param) {
        super(request, ref, opensearchSettings, param);
        this.payloadMandatory = true;

        allowedKeys.put("multitenancy_enabled", DataType.BOOLEAN);
        allowedKeys.put("private_tenant_enabled", DataType.BOOLEAN);
        allowedKeys.put("default_tenant", DataType.STRING);
    }
}
