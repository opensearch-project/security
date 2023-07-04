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

package com.amazon.dlic.auth.http.saml;

import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.time.Duration;

import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.opensaml.saml.metadata.resolver.impl.HTTPMetadataResolver;

import com.amazon.dlic.util.SettingsBasedSSLConfiguratorV4;

import org.opensearch.SpecialPermission;
import org.opensearch.common.settings.Settings;

public class SamlHTTPMetadataResolver extends HTTPMetadataResolver {

    SamlHTTPMetadataResolver(String idpMetadataUrl, Settings opensearchSettings, Path configPath) throws Exception {
        super(createHttpClient(opensearchSettings, configPath), idpMetadataUrl);
        setMinRefreshDelay(Duration.ofMillis(opensearchSettings.getAsLong("idp.min_refresh_delay", 60L * 1000L)));
        setMaxRefreshDelay(Duration.ofMillis(opensearchSettings.getAsLong("idp.max_refresh_delay", 14400000L)));
        setRefreshDelayFactor(opensearchSettings.getAsFloat("idp.refresh_delay_factor", 0.75f));
    }

    @Override
    @SuppressWarnings("removal")
    protected byte[] fetchMetadata() throws ResolverException {
        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<byte[]>() {
                @Override
                public byte[] run() throws ResolverException {
                    return SamlHTTPMetadataResolver.super.fetchMetadata();
                }
            });
        } catch (PrivilegedActionException e) {

            if (e.getCause() instanceof ResolverException) {
                throw (ResolverException) e.getCause();
            } else {
                throw new RuntimeException(e);
            }
        }
    }

    private static SettingsBasedSSLConfiguratorV4.SSLConfig getSSLConfig(Settings settings, Path configPath) throws Exception {
        return new SettingsBasedSSLConfiguratorV4(settings, configPath, "idp").buildSSLConfig();
    }

    @SuppressWarnings("removal")
    private static HttpClient createHttpClient(Settings settings, Path configPath) throws Exception {
        try {
            final SecurityManager sm = System.getSecurityManager();

            if (sm != null) {
                sm.checkPermission(new SpecialPermission());
            }

            return AccessController.doPrivileged(new PrivilegedExceptionAction<HttpClient>() {
                @Override
                public HttpClient run() throws Exception {
                    return createHttpClient0(settings, configPath);
                }
            });
        } catch (PrivilegedActionException e) {
            if (e.getCause() instanceof Exception) {
                throw (Exception) e.getCause();
            } else {
                throw new RuntimeException(e);
            }
        }
    }

    private static HttpClient createHttpClient0(Settings settings, Path configPath) throws Exception {

        HttpClientBuilder builder = HttpClients.custom();

        builder.useSystemProperties();

        SettingsBasedSSLConfiguratorV4.SSLConfig sslConfig = getSSLConfig(settings, configPath);

        if (sslConfig != null) {
            builder.setSSLSocketFactory(sslConfig.toSSLConnectionSocketFactory());
        }

        return builder.build();
    }

}
