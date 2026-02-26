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

package org.opensearch.security.auth.ldap2;

import java.net.URI;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.ldaptive.Connection;
import org.ldaptive.ConnectionFactory;

/**
 * Wrapper around ConnectionFactory that extracts the hostname from the LDAP URL
 * and stores it in ThreadLocal for use by SNISettingTLSSocketFactory.
 *
 * <p>This is necessary because JNDI LDAP resolves hostnames to IP addresses before
 * creating SSL sockets, making the hostname unavailable for SNI configuration.
 */
public class HostnameAwareConnectionFactory implements ConnectionFactory {

    private static final Logger log = LogManager.getLogger(HostnameAwareConnectionFactory.class);
    private static final Pattern LDAP_URL_PATTERN = Pattern.compile("ldaps?://([^:/]+)(?::(\\d+))?");

    private final ConnectionFactory delegate;
    private final String ldapUrl;

    public HostnameAwareConnectionFactory(ConnectionFactory delegate, String ldapUrl) {
        this.delegate = delegate;
        this.ldapUrl = ldapUrl;
    }

    @Override
    public Connection getConnection() throws org.ldaptive.LdapException {
        // Extract hostname from LDAP URL and set in ThreadLocal before getting connection
        String hostname = extractHostname(ldapUrl);
        if (hostname != null) {
            log.debug("Setting hostname for LDAP connection: {}", hostname);
            SNISettingTLSSocketFactory.setHostname(hostname);
        } else {
            log.debug("Could not extract hostname from LDAP URL: {}", ldapUrl);
        }

        // ThreadLocal is cleared in SNISettingTLSSocketFactory.configureSocket() after socket creation
        return delegate.getConnection();
    }

    /**
     * Extracts the hostname from an LDAP URL.
     * Handles space-separated multiple URLs by extracting the first one.
     *
     * @param url the LDAP URL (e.g., "ldaps://localhost:636" or "ldaps://server1:636 ldaps://server2:636")
     * @return the hostname, or null if extraction fails
     */
    static String extractHostname(String url) {
        if (url == null || url.isEmpty()) {
            return null;
        }

        // Handle space-separated multiple URLs - extract the first one
        String firstUrl = url.split("\\s+")[0];

        try {
            // Try parsing as URI first
            URI uri = new URI(firstUrl);
            if (uri.getHost() != null) {
                return uri.getHost();
            }
        } catch (Exception e) {
            // Fall through to regex pattern
        }

        // Fallback to regex pattern
        Matcher matcher = LDAP_URL_PATTERN.matcher(firstUrl);
        if (matcher.find()) {
            return matcher.group(1);
        }

        return null;
    }
}
