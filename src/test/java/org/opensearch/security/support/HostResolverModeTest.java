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

    @Test
    public void testEnumCount() {
        assertThat(HostResolverMode.values().length, is(2));
    }
}
