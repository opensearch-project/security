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

import java.util.Map;

import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.compress.NotXContentException;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.Strings;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.ssl.util.Utils;

/**
 * Validator for validating password and hash present in the payload
 */
public class CredentialsValidator extends AbstractConfigurationValidator {

    private final PasswordValidator passwordValidator;

    public CredentialsValidator(final RestRequest request,
                                final BytesReference ref,
                                final Settings opensearchSettings,
                                Object... param) {
        super(request, ref, opensearchSettings, param);
        this.payloadMandatory = true;
        this.passwordValidator = PasswordValidator.of(opensearchSettings);
        allowedKeys.put("hash", DataType.STRING);
        allowedKeys.put("password", DataType.STRING);
    }

    /**
     * Function to validate password in the content body.
     * @return true if validation is successful else false
     */
    @Override
    public boolean validate() {
        if (!super.validate()) {
            return false;
        }
        if ((request.method() == RestRequest.Method.PUT || request.method() == RestRequest.Method.PATCH)
                && this.content != null
                && this.content.length() > 1) {
            try {
                final Map<String, Object> contentAsMap = XContentHelper.convertToMap(this.content, false, XContentType.JSON).v2();
                final String password = (String) contentAsMap.get("password");
                if (password != null) {
                    // Password is not allowed to be empty if present.
                    if (password.isEmpty()) {
                        this.errorType = ErrorType.INVALID_PASSWORD;
                        return false;
                    }
                    final String username = Utils.coalesce(request.param("name"), hasParams() ? (String) param[0] : null);
                    if (Strings.isNullOrEmpty(username)) {
                        if (log.isDebugEnabled()) {
                            log.debug("Unable to validate username because no user is given");
                        }
                        return false;
                    }
                    final ErrorType passwordValidationResult = passwordValidator.validate(username, password);
                    if (passwordValidationResult != ErrorType.NONE) {
                        this.errorType = passwordValidationResult;
                        return false;
                    }
                }
            } catch (NotXContentException e) {
                //this.content is not valid json/yaml
                log.error("Invalid xContent: " + e, e);
                return false;
            }
        }
        return true;
    }

}
