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

package org.opensearch.security;

import org.junit.Test;
import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.SecurityUtils;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertThrows;

/**
 * FIPS variant of {@link UtilTests}. The baseline substitutes a three-character default into an
 * {@code ${envbc...}} placeholder and hashes it. Under FIPS that is not an inapplicable case but
 * a defined failure, so it is asserted rather than skipped: BC FIPS refuses key material below
 * the 112-bit floor. The positive path is already covered in both modes by
 * {@link UtilTests#testEnvReplacePBKDF2BCFips()}, which uses a long enough password.
 */
public class UtilFipsTests extends UtilTests {

    @Override
    @Test
    public void testEnvReplacePBKDF2() {
        final Settings settings = Settings.builder()
            .put(ConfigConstants.SECURITY_PASSWORD_HASHING_ALGORITHM, ConfigConstants.PBKDF2)
            .build();

        FipsUnapprovedOperationError error = assertThrows(
            FipsUnapprovedOperationError.class,
            () -> SecurityUtils.replaceEnvVars("${envbc.MYENV:-tTt}", settings)
        );
        assertThat(error.getMessage(), containsString("password must be at least 112 bits"));
    }
}
