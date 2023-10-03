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
import org.opensearch.security.filter.SecurityRequest;

import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.rest.RestRequest.Method.PUT;

public class AuthTokenUtils {
    private static final String ON_BEHALF_OF_SUFFIX = "api/generateonbehalfoftoken";
    private static final String ACCOUNT_SUFFIX = "api/account";

    public static Boolean isAccessToRestrictedEndpoints(final SecurityRequest request, final String suffix) {
        if (suffix == null) {
            return false;
        }
        switch (suffix) {
            case ON_BEHALF_OF_SUFFIX:
                return request.method() == POST;
            case ACCOUNT_SUFFIX:
                return request.method() == PUT;
            default:
                return false;
        }
    }

    public static Boolean isKeyNull(Settings settings, String key) {
        return settings.get(key) == null;
    }
}
