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

import java.util.Map;
import java.util.regex.Pattern;

import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.compress.NotXContentException;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;

import com.amazon.opendistroforelasticsearch.security.ssl.util.Utils;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;

public class InternalUsersValidator extends AbstractConfigurationValidator {

    public InternalUsersValidator(final RestRequest request, BytesReference ref, final Settings esSettings,
            Object... param) {
        super(request, ref, esSettings, param);
        this.payloadMandatory = true;
        allowedKeys.put("hash", DataType.STRING);
        allowedKeys.put("password", DataType.STRING);
        allowedKeys.put("backend_roles", DataType.ARRAY);
        allowedKeys.put("attributes", DataType.OBJECT);
        allowedKeys.put("description", DataType.STRING);
        allowedKeys.put("opendistro_security_roles", DataType.ARRAY);
    }

    @Override
    public boolean validate() {
        if(!super.validate()) {
            return false;
        }

        final String regex = this.esSettings.get(ConfigConstants.OPENDISTRO_SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX, null);

        if((request.method() == Method.PUT || request.method() == Method.PATCH )
                && regex != null
                && !regex.isEmpty()
                && this.content != null
                && this.content.length() > 1) {
            try {
                final Map<String, Object> contentAsMap = XContentHelper.convertToMap(this.content, false, XContentType.JSON).v2();
                if(contentAsMap != null && contentAsMap.containsKey("password")) {
                    final String password = (String) contentAsMap.get("password");

                    if(password == null || password.isEmpty()) {
                        if(log.isDebugEnabled()) {
                            log.debug("Unable to validate password because no password is given");
                        }
                        return false;
                    }

                    if(!regex.isEmpty() && !Pattern.compile("^"+regex+"$").matcher(password).matches()) {
                        if(log.isDebugEnabled()) {
                            log.debug("Regex does not match password");
                        }
                        this.errorType = ErrorType.INVALID_PASSWORD;
                        return false;
                    }

                    final String username = Utils.coalesce(request.param("name"), hasParams()?(String)param[0]:null);

                    if(username == null || username.isEmpty()) {
                        if(log.isDebugEnabled()) {
                            log.debug("Unable to validate username because no user is given");
                        }
                        return false;
                    }

                    if(username.toLowerCase().equals(password.toLowerCase())) {
                        if(log.isDebugEnabled()) {
                            log.debug("Username must not match password");
                        }
                        this.errorType = ErrorType.INVALID_PASSWORD;
                        return false;
                    }
                }
            } catch (NotXContentException e) {
                //this.content is not valid json/yaml
                log.error("Invalid xContent: "+e,e);
                return false;
            }
        }
        return true;
    }
}
