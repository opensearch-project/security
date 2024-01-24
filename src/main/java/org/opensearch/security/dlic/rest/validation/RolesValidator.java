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

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import org.opensearch.security.configuration.Salt;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestRequest;

import org.opensearch.security.configuration.MaskedField;

public class RolesValidator extends AbstractConfigurationValidator {

    private static final Salt SALT = new Salt(new byte[] {1,2,3,4,5,1,2,3,4,5,1,2,3,4,5,6});

	public RolesValidator(final RestRequest request, boolean isSuperAdmin, final BytesReference ref, final Settings opensearchSettings, Object... param) {
		super(request, ref, opensearchSettings, param);
		this.payloadMandatory = true;
        allowedKeys.put("cluster_permissions", DataType.ARRAY);
        allowedKeys.put("tenant_permissions", DataType.ARRAY);
        allowedKeys.put("index_permissions", DataType.ARRAY);
        allowedKeys.put("description", DataType.STRING);
        if (isSuperAdmin) allowedKeys.put("reserved", DataType.BOOLEAN);
	}

    @Override
    public boolean validate() {

        if (!super.validate()) {
            return false;
        }

        boolean valid=true;

        if (this.content != null && this.content.length() > 0) {

            ArrayNode indexPermissions = getContentAsNode().withArray("index_permissions");
            Set<String> maskedFields = new HashSet<>();
            if (indexPermissions != null) {
                for (JsonNode ip : indexPermissions) {
                    ip.withArray("masked_fields").forEach((n) -> maskedFields.add(n.asText()));
                }
            }

            for (String mf : maskedFields) {
                if (!validateMaskedFieldSyntax(mf)) {
                    valid = false;
                }
            }
        }

        if(!valid) {
           this.errorType = ErrorType.WRONG_DATATYPE;
        }

        return valid;
    }

    private boolean validateMaskedFieldSyntax(String mf) {
        try {
            new MaskedField(mf, SALT).isValid();
        } catch (Exception e) {
            wrongDatatypes.put("Masked field not valid: "+mf, e.getMessage());
            return false;
        }
        return true;
    }
}
