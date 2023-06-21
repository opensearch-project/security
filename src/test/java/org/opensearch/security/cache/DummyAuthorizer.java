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

package org.opensearch.security.cache;

import java.nio.file.Path;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.AuthorizationBackend;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;

public class DummyAuthorizer implements AuthorizationBackend {

    private static volatile long count;

    public DummyAuthorizer(final Settings settings, final Path configPath) {}

    @Override
    public String getType() {
        return "dummy";
    }

    @Override
    public void fillRoles(User user, AuthCredentials credentials) throws OpenSearchSecurityException {
        count++;
        user.addRole("role_" + user.getName() + "_" + System.currentTimeMillis() + "_" + count);

    }

    public static long getCount() {
        return count;
    }

    public static void reset() {
        count = 0;
    }

}
