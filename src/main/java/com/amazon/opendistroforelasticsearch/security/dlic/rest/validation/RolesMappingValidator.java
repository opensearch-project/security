/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
