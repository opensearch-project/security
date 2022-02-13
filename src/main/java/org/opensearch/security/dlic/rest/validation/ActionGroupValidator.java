/*
 * Copyright OpenSearch Contributors
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

package org.opensearch.security.dlic.rest.validation;

import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestRequest;

public class ActionGroupValidator extends AbstractConfigurationValidator {

	public ActionGroupValidator(final RestRequest request, boolean isSuperAdmin, BytesReference ref, final Settings opensearchSettings, Object... param) {
		super(request, ref, opensearchSettings, param);
		this.payloadMandatory = true;
		allowedKeys.put("allowed_actions", DataType.ARRAY);
	    allowedKeys.put("description", DataType.STRING);
	    allowedKeys.put("type", DataType.STRING);
	    if (isSuperAdmin) allowedKeys.put("reserved" , DataType.BOOLEAN);

		mandatoryKeys.add("allowed_actions");
	}

}
