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
import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import inet.ipaddr.IPAddressString;

/**
 * A utility class that performs matching of IP addresses against hostname patterns and CIDR ranges.
 * This matcher supports both wildcard hostname patterns (e.g., *.example.com) and CIDR notation (e.g., 192.168.1.0/24).
 */
public class HostAndCidrMatcher {
    protected final Logger log = LogManager.getLogger(HostAndCidrMatcher.class);
    private final WildcardMatcher hostMatcher;
    private final List<IPAddressString> cidrMatchers;

    /**
     * Constructs a new matcher with the specified host patterns.
     *
     * @param hostPatterns A list of patterns that can include both hostname wildcards
     *                     (e.g., *.example.com) and CIDR ranges (e.g., 192.168.1.0/24).
     *                     Must not be null.
     * @throws IllegalArgumentException if hostPatterns is null
     */
    public HostAndCidrMatcher(List<String> hostPatterns) {
        if (hostPatterns == null) {
            throw new IllegalArgumentException("Host patterns cannot be null");
        }

        this.hostMatcher = WildcardMatcher.from(hostPatterns);
        this.cidrMatchers = hostPatterns.stream().map(IPAddressString::new).filter(IPAddressString::isIPAddress).toList();
    }

    /**
     * Checks if the provided IP address matches any of the configured CIDR ranges.
     *
     * @param address The IP address to check. Can be either IPv4 or IPv6.
     * @return true if the address matches any configured CIDR range, false otherwise
     *         or if the address is null
     */
    public boolean matchesCidr(InetAddress address) {
        if (address == null || cidrMatchers == null) {
            return false;
        }

        IPAddressString addressString = new IPAddressString(address.getHostAddress());
        return cidrMatchers.stream().anyMatch(cidrAddress -> cidrAddress.contains(addressString));
    }

    /**
     * Checks if the provided IP address matches any of the configured hostname patterns.
     * This method can perform DNS lookups depending on the hostResolverMode.
     *
     * @param address The IP address to check
     * @param hostResolverMode The resolution mode. Must be one of {@link HostResolverMode} to enable hostname matching
     * @return true if the address matches any configured hostname pattern, false otherwise,
     *         if the address is null, or if the resolver mode is invalid
     * @implNote This method may perform DNS lookups which could impact performance
     */
    public boolean matchesHostname(InetAddress address, String hostResolverMode) {
        if (address == null || hostMatcher == null) {
            return false;
        }

        List<String> valuesToCheck = new ArrayList<>(List.of(address.getHostAddress()));
        if (hostResolverMode != null
            && (hostResolverMode.equalsIgnoreCase(HostResolverMode.IP_HOSTNAME.getValue())
                || hostResolverMode.equalsIgnoreCase(HostResolverMode.IP_HOSTNAME_LOOKUP.getValue()))) {
            try {
                final String hostName = address.getHostName();  // potential blocking call
                valuesToCheck.add(hostName);
            } catch (Exception e) {
                log.warn("Failed to resolve hostname for {}: {}", address.getHostAddress(), e.getMessage());
                return false;
            }
        }
        return valuesToCheck.stream().anyMatch(hostMatcher);
    }

    /**
     * Checks if the provided IP address matches either hostname patterns or CIDR ranges.
     *
     * @param address The IP address to check
     * @param hostResolverMode The resolution mode for hostname matching
     * @return true if the address matches either hostname patterns or CIDR ranges,
     *         false otherwise
     */
    public boolean matches(InetAddress address, String hostResolverMode) {
        return matchesHostname(address, hostResolverMode) || matchesCidr(address);
    }
}
