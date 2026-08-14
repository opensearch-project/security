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

package org.opensearch.security.api;

import org.junit.Test;

import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.test.framework.matcher.RestMatchers.isBadRequest;
import static org.opensearch.test.framework.matcher.RestMatchers.isCreated;

/**
 * FIPS variant of {@link InternalUsersRestApiIntegrationTest}. Under FIPS the API enforces a
 * minimum password length so that no FIPS-approved KDF is ever handed material below the
 * 112-bit floor; outside FIPS there is no such floor to exercise.
 */
public class InternalUsersRestApiIntegrationFipsIT extends InternalUsersRestApiIntegrationTest {

    @Test
    public void changingPasswordBelowFipsFloorIsRejected() throws Exception {
        try (TestRestClient client = localCluster.getAdminCertRestClient()) {
            final var username = randomAsciiAlphanumOfLength(10);

            // 1. Create the user with a password that clears the 14-char FIPS floor.
            assertThat(
                client.putJson(apiPath(username), internalUserWithPassword(randomAsciiAlphanumOfLength(FIPS_MIN_PASSWORD_LENGTH))),
                isCreated()
            );

            // 2. Change the password to one below the floor -> clean 400, not a hang.
            assertThat(
                client.putJson(apiPath(username), internalUserWithPassword(randomAsciiAlphanumOfLength(FIPS_MIN_PASSWORD_LENGTH - 1))),
                isBadRequest()
            );
        }
    }
}
