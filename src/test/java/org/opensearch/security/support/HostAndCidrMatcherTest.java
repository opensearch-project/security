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

import java.net.InetAddress;
import java.util.Arrays;
import java.util.Collections;

import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class HostAndCidrMatcherTest {

    private static final String OPENSEARCH_DOMAIN = "*.opensearch.org";
    private static final String OPENSEARCH_WWW = "www.opensearch.org";
    private static final String EXAMPLE_DOMAIN = "*.example.com";
    private static final String EXAMPLE_WWW = "www.example.com";

    // CIDR ranges
    private static final String PRIVATE_CLASS_A_CIDR = "10.0.0.0/8";
    private static final String PRIVATE_CLASS_B_CIDR = "172.16.0.0/12";
    private static final String PRIVATE_CLASS_C_CIDR = "192.168.1.0/24";
    private static final String IPV6_DOCUMENTATION_CIDR = "2001:db8::/32";

    // IP addresses within the CIDR ranges
    private static final String PRIVATE_CLASS_A_IP = "10.10.10.10";
    private static final String PRIVATE_CLASS_B_IP = "172.16.1.1";
    private static final String PRIVATE_CLASS_C_IP = "192.168.1.100";
    private static final String IPV6_DOCUMENTATION_IP = "2001:db8:1:2::";

    private HostAndCidrMatcher matcher;

    @Test(expected = IllegalArgumentException.class)
    public void constructorShouldThrowExceptionForNullInput() {
        new HostAndCidrMatcher(null);
    }

    @Test
    public void shouldReturnFalseForEmptyResolverMode() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(OPENSEARCH_DOMAIN));
        InetAddress address = InetAddress.getByName(OPENSEARCH_WWW);
        assertThat(matcher.matchesHostname(address, ""), is(false));
    }

    @Test
    public void shouldReturnFalseForInvalidResolverMode() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(OPENSEARCH_DOMAIN));
        InetAddress address = InetAddress.getByName(OPENSEARCH_WWW);
        assertThat(matcher.matchesHostname(address, "invalid-mode"), is(false));
    }

    @Test
    public void shouldReturnFalseForNullResolverMode() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(OPENSEARCH_DOMAIN));
        InetAddress address = InetAddress.getByName(OPENSEARCH_WWW);
        assertThat(matcher.matchesHostname(address, null), is(false));
    }

    @Test
    public void shouldReturnFalseForWrongCaseResolverMode() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(OPENSEARCH_DOMAIN));
        InetAddress address = InetAddress.getByName(OPENSEARCH_WWW);
        assertThat(matcher.matchesHostname(address, "IP_HOSTNAME"), is(false));
    }

    @Test
    public void shouldReturnTrueForExactMatch() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList("127.0.0.1"));
        InetAddress address = InetAddress.getByName("127.0.0.1");
        assertThat(matcher.matchesHostname(address, "ip-only"), is(true));
    }

    @Test
    public void shouldReturnTrueForIpPatternMatch() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList("127.0.0.*"));
        InetAddress address = InetAddress.getByName("127.0.0.1");
        assertThat(matcher.matchesHostname(address, "ip-only"), is(true));
    }

    @Test
    public void shouldReturnFalseForHostMatchWithIpResolve() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList("127.0.0.1"));
        InetAddress address = InetAddress.getByName("localhost");
        assertThat(matcher.matchesHostname(address, "ip-only"), is(true));
    }

    @Test
    public void shouldReturnTrueForHostMatchWithIpResolve() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList("127.0.0.1"));
        InetAddress address = InetAddress.getByName("localhost");
        assertThat(matcher.matchesHostname(address, "ip-hostname"), is(true));
    }

    @Test
    public void shouldMatchIpv4WithinCidrRange() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(PRIVATE_CLASS_C_CIDR, PRIVATE_CLASS_A_CIDR));
        InetAddress address = InetAddress.getByName(PRIVATE_CLASS_C_IP);
        assertThat(matcher.matchesCidr(address), is(true));
    }

    @Test
    public void shouldNotMatchIpv4OutsideCidrRange() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(PRIVATE_CLASS_C_CIDR, PRIVATE_CLASS_A_CIDR));
        InetAddress address = InetAddress.getByName("192.168.2.100");
        assertThat(matcher.matchesCidr(address), is(false));
    }

    @Test
    public void shouldMatchIpv6WithinCidrRange() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(IPV6_DOCUMENTATION_CIDR));
        InetAddress address = InetAddress.getByName(IPV6_DOCUMENTATION_IP);
        assertThat(matcher.matchesCidr(address), is(true));
    }

    @Test
    public void shouldHandleNullAddressInCidrMatching() {
        matcher = new HostAndCidrMatcher(Arrays.asList(PRIVATE_CLASS_C_CIDR));
        assertThat(matcher.matchesCidr(null), is(false));
    }

    @Test
    public void shouldMatchValidHostnamePattern() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(EXAMPLE_DOMAIN, OPENSEARCH_WWW));
        InetAddress address = InetAddress.getByName(EXAMPLE_WWW);
        assertThat(matcher.matchesHostname(address, "ip-hostname"), is(true));
    }

    @Test
    public void shouldHandleNullAddressInHostnameMatching() {
        matcher = new HostAndCidrMatcher(Arrays.asList(EXAMPLE_DOMAIN));
        assertThat(matcher.matchesHostname(null, "ip-hostname"), is(false));
    }

    @Test
    public void shouldMatchWhenIpMatchesCidrOnly() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(EXAMPLE_DOMAIN, PRIVATE_CLASS_C_CIDR));
        InetAddress address = InetAddress.getByName(PRIVATE_CLASS_C_IP);
        assertThat(matcher.matches(address, "ip-hostname"), is(true));
    }

    @Test
    public void shouldMatchWhenHostnameMatchesOnly() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(EXAMPLE_DOMAIN, PRIVATE_CLASS_C_CIDR));
        InetAddress address = InetAddress.getByName(EXAMPLE_WWW);
        assertThat(matcher.matches(address, "ip-hostname"), is(true));
    }

    @Test
    public void shouldNotMatchWhenNeitherMatches() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(EXAMPLE_DOMAIN, PRIVATE_CLASS_C_CIDR));
        InetAddress address = InetAddress.getByName(OPENSEARCH_WWW);
        assertThat(matcher.matches(address, "ip-hostname"), is(false));
    }

    @Test
    public void shouldHandleEmptyPatternList() throws Exception {
        matcher = new HostAndCidrMatcher(Collections.emptyList());
        InetAddress address = InetAddress.getByName(PRIVATE_CLASS_C_IP);
        assertThat(matcher.matches(address, "ip-hostname"), is(false));
    }

    @Test
    public void shouldHandleInvalidCidrNotation() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList("invalid/cidr/notation"));
        InetAddress address = InetAddress.getByName(PRIVATE_CLASS_C_IP);
        assertThat(matcher.matchesCidr(address), is(false));
    }

    @Test
    public void shouldMatchIpHostnameLookupMode() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(OPENSEARCH_DOMAIN));
        InetAddress address = InetAddress.getByName(OPENSEARCH_WWW);
        assertThat(matcher.matchesHostname(address, "ip-hostname-lookup"), is(true));
    }

    @Test
    public void shouldHandleMultipleCidrRanges() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(PRIVATE_CLASS_C_CIDR, PRIVATE_CLASS_A_CIDR, PRIVATE_CLASS_B_CIDR));
        InetAddress address1 = InetAddress.getByName(PRIVATE_CLASS_C_IP);
        InetAddress address2 = InetAddress.getByName(PRIVATE_CLASS_A_IP);
        InetAddress address3 = InetAddress.getByName(PRIVATE_CLASS_B_IP);

        assertThat(matcher.matchesCidr(address1), is(true));
        assertThat(matcher.matchesCidr(address2), is(true));
        assertThat(matcher.matchesCidr(address3), is(true));
    }

    @Test
    public void shouldHandleMultipleHostnamePatterns() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(EXAMPLE_DOMAIN, OPENSEARCH_DOMAIN));
        InetAddress address1 = InetAddress.getByName(EXAMPLE_WWW);
        InetAddress address2 = InetAddress.getByName(OPENSEARCH_WWW);

        assertThat(matcher.matchesHostname(address1, "ip-hostname"), is(true));
        assertThat(matcher.matchesHostname(address2, "ip-hostname"), is(true));
    }

    @Test
    public void shouldHandleMixedIpv4AndIpv6Patterns() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(PRIVATE_CLASS_C_CIDR, IPV6_DOCUMENTATION_CIDR, EXAMPLE_DOMAIN));
        InetAddress ipv4Address = InetAddress.getByName(PRIVATE_CLASS_C_IP);
        InetAddress ipv6Address = InetAddress.getByName(IPV6_DOCUMENTATION_IP);

        assertThat(matcher.matchesCidr(ipv4Address), is(true));
        assertThat(matcher.matchesCidr(ipv6Address), is(true));
    }
}
