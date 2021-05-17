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

package org.opensearch.security.dlic.rest.validation;

import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestRequest;

/**
 * Validator for Internal Users Api Action.
 */
public class InternalUsersValidator extends CredentialsValidator {

    public InternalUsersValidator(final RestRequest request, boolean isSuperAdmin, BytesReference ref, final Settings opensearchSettings,
            Object... param) {
        super(request, ref, opensearchSettings, param);
        allowedKeys.put("backend_roles", DataType.ARRAY);
        allowedKeys.put("attributes", DataType.OBJECT);
        allowedKeys.put("description", DataType.STRING);
        allowedKeys.put("opendistro_security_roles", DataType.ARRAY);
        if (isSuperAdmin) allowedKeys.put("reserved", DataType.BOOLEAN);
    }
}
