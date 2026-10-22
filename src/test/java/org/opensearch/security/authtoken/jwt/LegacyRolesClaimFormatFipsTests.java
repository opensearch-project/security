/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.authtoken.jwt;

import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

/**
 * FIPS variant of {@link LegacyRolesClaimFormatTest}. Reading is identical under FIPS: a cluster that ran
 * an earlier version on BC FIPS did issue AES/ECB tokens, because the module permits that primitive in
 * approved-only mode, so those tokens have to survive the upgrade window like any other. Writing is what
 * differs, since AES/ECB is not an approved mode for confidentiality (NIST SP 800-38A). Everything the
 * baseline asserts about reading is therefore inherited and re-run against the FIPS providers.
 */
public class LegacyRolesClaimFormatFipsTests extends LegacyRolesClaimFormatTest {

    /** Even a cluster that still contains a pre-upgrade node does not get the unapproved format written. */
    @Test
    @Override
    public void testWritesLegacyFormatWhileAPreUpgradeNodeIsPresent() {
        EncryptionDecryptionUtil util = new EncryptionDecryptionUtil(encodedKey, legacyFormatInUse(true));

        String encrypted = util.encrypt("Hello, OpenSearch!");

        assertThat(encrypted, not(is(encryptWithLegacyEcb(encodedKey, "Hello, OpenSearch!"))));
        assertThat(util.decrypt(encrypted), is("Hello, OpenSearch!"));
    }

    /** Nor the pinned value: under FIPS the claim is AES-GCM, which this node reads back itself. */
    @Test
    @Override
    public void testWritesPinnedLegacyValueForAnOlderVersion() {
        EncryptionDecryptionUtil util = new EncryptionDecryptionUtil(PINNED_KEY, legacyFormatInUse(true));

        String encrypted = util.encrypt("role1,role2");

        assertThat(encrypted, not(is(PINNED_CIPHERTEXT)));
        assertThat(util.decrypt(encrypted), is("role1,role2"));
    }
}
