/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

package org.opensearch.security.auth;

import java.util.Collections;
import java.util.Optional;
import java.util.Set;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.filter.SecurityResponse;
import org.opensearch.security.user.AuthCredentials;

/**
 * OpenSearch Security custom HTTP authenticators need to implement this interface.
 * <p/>
 * A HTTP authenticator extracts {@link AuthCredentials} from a {@link RestRequest}
 * <p/>
 *
 * Implementation classes must provide a public constructor
 * <p/>
 * {@code public MyHTTPAuthenticator(org.opensearch.common.settings.Settings settings, java.nio.file.Path configPath)}
 * <p/>
 * The constructor should not throw any exception in case of an initialization problem.
 * Instead catch all exceptions and log a appropriate error message. A logger can be instantiated like:
 * <p/>
 * {@code private final Logger log = LogManager.getLogger(this.getClass());}
 * <p/>
 */
public interface HTTPAuthenticator {

    /**
     * The type (name) of the authenticator. Only for logging.
     * @return the type
     */
    String getType();

    /**
     * Extract {@link AuthCredentials} from {@link RestRequest}
     *
     * @param request The rest request
     * @param context The current thread context
     * @return The authentication credentials (complete or incomplete) or null when no credentials are found in the request
     * <p>
     * When the credentials could be fully extracted from the request {@code .markComplete()} must be called on the {@link AuthCredentials} which are returned.
     * If the authentication flow needs another roundtrip with the request originator do not mark it as complete.
     * @throws OpenSearchSecurityException
     */
    AuthCredentials extractCredentials(final SecurityRequest request, final ThreadContext context) throws OpenSearchSecurityException;

    /**
     * If the {@code extractCredentials()} call was not successful or the authentication flow needs another roundtrip this method
     * will be called. If the custom HTTP authenticator does not support this method is a no-op and null response should be returned.
     * If the custom HTTP authenticator does support re-request authentication or supports authentication flows with multiple roundtrips
     * then the response will be returned which can then be sent via response channel.
     *
     * @param request The request to reauthenticate or not
     * @param credentials The credentials from the prior authentication attempt
     * @return Optional response if is not supported/necessary, response object otherwise.
     */
    Optional<SecurityResponse> reRequestAuthentication(final SecurityRequest request, AuthCredentials credentials);

    /**
     * Indicates whether this authenticator supports user impersonation.
     *
     * @return true if impersonation is supported, false otherwise.
     */
    default boolean supportsImpersonation() {
        return true;
    }

    /**
     * Returns a set of URL parameters this authenticator supports that are considered sensitive
     * and should be redacted in the audit logs
     *
     * @return The set of URL parameters considered sensitive for this authenticator.
     */
    default Set<String> getSensitiveUrlParams() {
        return Collections.emptySet();
    }
}
