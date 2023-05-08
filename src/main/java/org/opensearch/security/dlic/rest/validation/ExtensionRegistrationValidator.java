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

/**
 * Validator for Internal Users Api Action.
 */
public class ExtensionRegistrationValidator extends AbstractConfigurationValidator {

    public ExtensionRegistrationValidator(final RestRequest request, boolean isSuperAdmin, BytesReference ref, final Settings opensearchSettings,
            Object... param) {
        super(request, ref, opensearchSettings, param);
        allowedKeys.put("unique_id", DataType.STRING);
        allowedKeys.put("description", DataType.STRING);
        allowedKeys.put("indices", DataType.ARRAY);
        allowedKeys.put("protected_indices", DataType.ARRAY);
        allowedKeys.put("endpoints", DataType.ARRAY);
        allowedKeys.put("protected_endpoints", DataType.ARRAY);
    }

    @Override
    public boolean validate() {
        //TODO
        return true;


    }
}