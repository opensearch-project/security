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

import java.util.List;

import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestRequest;

import com.amazon.opendistroforelasticsearch.security.configuration.MaskedField;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.ReadContext;

public class RolesValidator extends AbstractConfigurationValidator {

	public RolesValidator(final RestRequest request, final BytesReference ref, final Settings esSettings, Object... param) {
		super(request, ref, esSettings, param);
		this.payloadMandatory = true;
        allowedKeys.put("cluster_permissions", DataType.ARRAY);
        allowedKeys.put("tenant_permissions", DataType.ARRAY);
        allowedKeys.put("index_permissions", DataType.ARRAY);
        allowedKeys.put("description", DataType.STRING);
	}

    @Override
    public boolean validate() {

        if (!super.validate()) {
            return false;
        }

        boolean valid=true;

        if (this.content != null && this.content.length() > 0) {

            final ReadContext ctx = JsonPath.parse(this.content.utf8ToString());
            final List<String> maskedFields = ctx.read("$..masked_fields[*]");

            if (maskedFields != null) {

                for (String mf : maskedFields) {
                    if (!validateMaskedFieldSyntax(mf)) {
                        valid = false;
                    }
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
            new MaskedField(mf, new byte[] {1,2,3,4,5,1,2,3,4,5,1,2,3,4,5,6}).isValid();
        } catch (Exception e) {
            wrongDatatypes.put("Masked field not valid: "+mf, e.getMessage());
            return false;
        }
        return true;
    }
}
