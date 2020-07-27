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

package com.amazon.opendistroforelasticsearch.security.dlic.rest.validation;

import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestRequest;

public class AuditLogValidator extends AbstractConfigurationValidator {
    public AuditLogValidator(final RestRequest request, final BytesReference ref, final Settings esSettings, final Object... param)  {
        super(request, ref, esSettings, param);
        allowedKeys.put("category", DataType.STRING);
        allowedKeys.put("user", DataType.STRING);
        allowedKeys.put("privilege", DataType.STRING);
        allowedKeys.put("headers", DataType.OBJECT);
        allowedKeys.put("remote", DataType.STRING);
        mandatoryKeys.add("category");
    }
}
