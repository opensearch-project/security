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

package org.opensearch.security.util;

import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestRequest;

public class AuthTokenUtils {
    private static final String ON_BEHALF_OF_SUFFIX = "api/generateonbehalfoftoken";
    private static final String ACCOUNT_SUFFIX = "api/account";

    public static Boolean isAccessToOBOEndpoint(final RestRequest request, final String suffix) {
        return request.method() == RestRequest.Method.POST && ON_BEHALF_OF_SUFFIX.equals(suffix);
    }

    public static Boolean isAccessToPasswordChangingEndpoint(final RestRequest request, final String suffix) {
        return request.method() == RestRequest.Method.PUT && ACCOUNT_SUFFIX.equals(suffix);
    }

    public static Boolean isSigningKeyNull(Settings settings) {
        return settings.get("signing_key") == null;
    }

    public static Boolean isEncryptionKeyNull(Settings settings) {
        return settings.get("encryption_key") == null;
    }
}
