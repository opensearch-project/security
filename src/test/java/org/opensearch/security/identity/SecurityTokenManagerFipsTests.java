/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.identity;

import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

/**
 * FIPS variant of {@link SecurityTokenManagerTest}. Outside FIPS mode a cluster that still holds a
 * pre-upgrade node gets its roles claim written in the old AES/ECB format, so that node can read it. Under
 * FIPS that format is never written, whatever the cluster looks like, because AES/ECB is not an approved
 * mode for confidentiality (NIST SP 800-38A). That has a price: a FIPS cluster does hold pre-upgrade nodes
 * during a rolling upgrade (earlier versions ran on BC FIPS and issued AES/ECB tokens), and those nodes
 * reject every token an upgraded node issues until they are upgraded themselves.
 */
public class SecurityTokenManagerFipsTests extends SecurityTokenManagerTest {

    @Test
    @Override
    public void issueOnBehalfOfToken_writesPreUpgradeFormatWhileAnOldNodeIsInTheCluster() throws Exception {
        clusterOf(true);

        final String rolesClaim = issueAndCaptureRolesClaim();

        assertThat(readWithoutLegacyFormat(rolesClaim), is(OBO_ROLE));
    }
}
