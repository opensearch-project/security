package org.opensearch.security.support;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.Collections;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

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
        assertFalse(matcher.matchesHostname(address, ""));
    }

    @Test
    public void shouldReturnFalseForInvalidResolverMode() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(OPENSEARCH_DOMAIN));
        InetAddress address = InetAddress.getByName(OPENSEARCH_WWW);
        assertFalse(matcher.matchesHostname(address, "invalid-mode"));
    }

    @Test
    public void shouldReturnFalseForNullResolverMode() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(OPENSEARCH_DOMAIN));
        InetAddress address = InetAddress.getByName(OPENSEARCH_WWW);
        assertFalse(matcher.matchesHostname(address, null));
    }

    @Test
    public void shouldReturnFalseForWrongCaseResolverMode() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(OPENSEARCH_DOMAIN));
        InetAddress address = InetAddress.getByName(OPENSEARCH_WWW);
        assertFalse(matcher.matchesHostname(address, "IP_HOSTNAME"));
    }

    @Test
    public void shouldMatchIpv4WithinCidrRange() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(PRIVATE_CLASS_C_CIDR, PRIVATE_CLASS_A_CIDR));
        InetAddress address = InetAddress.getByName(PRIVATE_CLASS_C_IP);
        assertTrue(matcher.matchesCidr(address));
    }

    @Test
    public void shouldNotMatchIpv4OutsideCidrRange() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(PRIVATE_CLASS_C_CIDR, PRIVATE_CLASS_A_CIDR));
        InetAddress address = InetAddress.getByName("192.168.2.100");
        assertFalse(matcher.matchesCidr(address));
    }

    @Test
    public void shouldMatchIpv6WithinCidrRange() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(IPV6_DOCUMENTATION_CIDR));
        InetAddress address = InetAddress.getByName(IPV6_DOCUMENTATION_IP);
        assertTrue(matcher.matchesCidr(address));
    }

    @Test
    public void shouldHandleNullAddressInCidrMatching() {
        matcher = new HostAndCidrMatcher(Arrays.asList(PRIVATE_CLASS_C_CIDR));
        assertFalse(matcher.matchesCidr(null));
    }

    @Test
    public void shouldMatchValidHostnamePattern() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(EXAMPLE_DOMAIN, OPENSEARCH_WWW));
        InetAddress address = InetAddress.getByName(EXAMPLE_WWW);
        assertTrue(matcher.matchesHostname(address, "ip-hostname"));
    }

    @Test
    public void shouldHandleNullAddressInHostnameMatching() {
        matcher = new HostAndCidrMatcher(Arrays.asList(EXAMPLE_DOMAIN));
        assertFalse(matcher.matchesHostname(null, "ip-hostname"));
    }

    @Test
    public void shouldMatchWhenIpMatchesCidrOnly() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(EXAMPLE_DOMAIN, PRIVATE_CLASS_C_CIDR));
        InetAddress address = InetAddress.getByName(PRIVATE_CLASS_C_IP);
        assertTrue(matcher.matches(address, "ip-hostname"));
    }

    @Test
    public void shouldMatchWhenHostnameMatchesOnly() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(EXAMPLE_DOMAIN, PRIVATE_CLASS_C_CIDR));
        InetAddress address = InetAddress.getByName(EXAMPLE_WWW);
        assertTrue(matcher.matches(address, "ip-hostname"));
    }

    @Test
    public void shouldNotMatchWhenNeitherMatches() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(EXAMPLE_DOMAIN, PRIVATE_CLASS_C_CIDR));
        InetAddress address = InetAddress.getByName(OPENSEARCH_WWW);
        assertFalse(matcher.matches(address, "ip-hostname"));
    }

    @Test
    public void shouldHandleEmptyPatternList() throws Exception {
        matcher = new HostAndCidrMatcher(Collections.emptyList());
        InetAddress address = InetAddress.getByName(PRIVATE_CLASS_C_IP);
        assertFalse(matcher.matches(address, "ip-hostname"));
    }

    @Test
    public void shouldHandleInvalidCidrNotation() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList("invalid/cidr/notation"));
        InetAddress address = InetAddress.getByName(PRIVATE_CLASS_C_IP);
        assertFalse(matcher.matchesCidr(address));
    }

    @Test(expected = Exception.class)
    public void shouldHandleMalformedIpAddresses() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(PRIVATE_CLASS_C_CIDR));
        InetAddress address = InetAddress.getByName("invalid.ip.address");
        matcher.matchesCidr(address);
    }

    @Test
    public void shouldMatchIpHostnameLookupMode() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(OPENSEARCH_DOMAIN));
        InetAddress address = InetAddress.getByName(OPENSEARCH_WWW);
        assertTrue(matcher.matchesHostname(address, "ip-hostname-lookup"));
    }

    @Test
    public void shouldHandleMultipleCidrRanges() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(PRIVATE_CLASS_A_CIDR, PRIVATE_CLASS_B_CIDR, PRIVATE_CLASS_C_CIDR));

        InetAddress address1 = InetAddress.getByName(PRIVATE_CLASS_A_IP);
        InetAddress address2 = InetAddress.getByName(PRIVATE_CLASS_B_IP);
        InetAddress address3 = InetAddress.getByName(PRIVATE_CLASS_C_IP);

        assertTrue(matcher.matchesCidr(address1));
        assertTrue(matcher.matchesCidr(address2));
        assertTrue(matcher.matchesCidr(address3));
    }

    @Test
    public void shouldHandleMultipleHostnamePatterns() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(EXAMPLE_DOMAIN, OPENSEARCH_DOMAIN));
        InetAddress address1 = InetAddress.getByName(EXAMPLE_WWW);
        InetAddress address2 = InetAddress.getByName(OPENSEARCH_WWW);

        assertTrue(matcher.matchesHostname(address1, "ip-hostname"));
        assertTrue(matcher.matchesHostname(address2, "ip-hostname"));
    }

    @Test
    public void shouldHandleMixedIpv4AndIpv6Patterns() throws Exception {
        matcher = new HostAndCidrMatcher(Arrays.asList(PRIVATE_CLASS_C_CIDR, IPV6_DOCUMENTATION_CIDR, EXAMPLE_DOMAIN));
        InetAddress ipv4Address = InetAddress.getByName(PRIVATE_CLASS_C_IP);
        InetAddress ipv6Address = InetAddress.getByName(IPV6_DOCUMENTATION_IP);

        assertTrue(matcher.matchesCidr(ipv4Address));
        assertTrue(matcher.matchesCidr(ipv6Address));
    }
}
