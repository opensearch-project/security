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

public class RolesMappingValidator extends AbstractConfigurationValidator {

	public RolesMappingValidator(final RestRequest request, boolean isSuperAdmin, final BytesReference ref, final Settings opensearchSettings, Object... param) {
		super(request, ref, opensearchSettings, param);
		this.payloadMandatory = true;
		allowedKeys.put("backend_roles", DataType.ARRAY);
		allowedKeys.put("and_backend_roles", DataType.ARRAY);
		allowedKeys.put("hosts", DataType.ARRAY);
		allowedKeys.put("users", DataType.ARRAY);
		allowedKeys.put("description", DataType.STRING);
		if (isSuperAdmin) allowedKeys.put("reserved", DataType.BOOLEAN);

		mandatoryOrKeys.add("backend_roles");
		mandatoryOrKeys.add("and_backend_roles");
		mandatoryOrKeys.add("hosts");
		mandatoryOrKeys.add("users");
	}
}
