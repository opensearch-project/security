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

package org.opensearch.security.support;

import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class HostResolverModeTest {

    @Test
    public void testIpHostnameValue() {
        assertThat(HostResolverMode.IP_HOSTNAME.getValue(), is("ip-hostname"));
    }

    @Test
    public void testIpHostnameLookupValue() {
        assertThat(HostResolverMode.IP_HOSTNAME_LOOKUP.getValue(), is("ip-hostname-lookup"));
    }
}
