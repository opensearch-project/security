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
import java.util.Optional;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.AuthenticationBackend;
import org.opensearch.security.auth.AuthenticationContext;
import org.opensearch.security.auth.ImpersonationBackend;
import org.opensearch.security.user.User;

public class DummyAuthenticationBackend implements AuthenticationBackend, ImpersonationBackend {

    private static volatile long authCount;
    private static volatile long existsCount;

    public DummyAuthenticationBackend(final Settings settings, final Path configPath) {}

    @Override
    public String getType() {
        return "dummy";
    }

    @Override
    public User authenticate(AuthenticationContext context) throws OpenSearchSecurityException {
        authCount++;
        return new User(context.getCredentials().getUsername());
    }

    @Override
    public Optional<User> impersonate(User user) {
        existsCount++;
        return Optional.of(user);
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
