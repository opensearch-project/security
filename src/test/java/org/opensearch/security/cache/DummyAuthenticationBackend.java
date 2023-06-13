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
import org.opensearch.security.auth.AuthenticationBackend;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.user.User;

public class DummyAuthenticationBackend implements AuthenticationBackend {

    private static volatile long authCount;
    private static volatile long existsCount;

    public DummyAuthenticationBackend(final Settings settings, final Path configPath) {}

    @Override
    public String getType() {
        return "dummy";
    }

    @Override
    public User authenticate(AuthCredentials credentials) throws OpenSearchSecurityException {
        authCount++;
        return new User(credentials.getUsername());
    }

    @Override
    public boolean exists(User user) {
        existsCount++;
        return true;
    }

    public static long getAuthCount() {
        return authCount;
    }

    public static long getExistsCount() {
        return existsCount;
    }

    public static void reset() {
        authCount = 0;
        existsCount = 0;
    }
}
