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
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.auth.HTTPAuthenticator;
import org.opensearch.security.filter.SecurityRequestChannel;
import org.opensearch.security.user.AuthCredentials;

public class DummyHTTPAuthenticator implements HTTPAuthenticator {

    private static volatile long count;

    public DummyHTTPAuthenticator(final Settings settings, final Path configPath) {}

    @Override
    public String getType() {
        return "dummy";
    }

    @Override
    public AuthCredentials extractCredentials(final SecurityRequestChannel request, final ThreadContext context)
        throws OpenSearchSecurityException {
        count++;
        return new AuthCredentials("dummy").markComplete();
    }

    @Override
    public boolean reRequestAuthentication(SecurityRequestChannel channel, AuthCredentials credentials) {
        return false;
    }

    public static long getCount() {
        return count;
    }

    public static void reset() {
        count = 0;
    }
}
