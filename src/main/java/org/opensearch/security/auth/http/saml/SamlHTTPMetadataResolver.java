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

package org.opensearch.security.auth.http.saml;

import java.nio.file.Path;
import java.time.Duration;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;

import org.opensearch.common.settings.Settings;
import org.opensearch.secure_sm.AccessController;
import org.opensearch.security.util.SettingsBasedSSLConfiguratorV4;

import net.shibboleth.shared.resolver.ResolverException;
import org.opensaml.saml.metadata.resolver.impl.HTTPMetadataResolver;

public class SamlHTTPMetadataResolver extends HTTPMetadataResolver {

    SamlHTTPMetadataResolver(String idpMetadataUrl, Settings opensearchSettings, Path configPath) throws Exception {
        super(createHttpClient(opensearchSettings, configPath), idpMetadataUrl);
        setMinRefreshDelay(Duration.ofMillis(opensearchSettings.getAsLong("idp.min_refresh_delay", 60L * 1000L)));
        setMaxRefreshDelay(Duration.ofMillis(opensearchSettings.getAsLong("idp.max_refresh_delay", 14400000L)));
        setRefreshDelayFactor(opensearchSettings.getAsFloat("idp.refresh_delay_factor", 0.75f));
    }

    @Override
    protected byte[] fetchMetadata() throws ResolverException {
        return AccessController.doPrivilegedChecked(SamlHTTPMetadataResolver.super::fetchMetadata);
    }

    private static SettingsBasedSSLConfiguratorV4.SSLConfig getSSLConfig(Settings settings, Path configPath) throws Exception {
        return new SettingsBasedSSLConfiguratorV4(settings, configPath, "idp").buildSSLConfig();
    }

    private static HttpClient createHttpClient(Settings settings, Path configPath) throws Exception {
        try {
            return AccessController.doPrivilegedChecked(() -> createHttpClient0(settings, configPath));
        } catch (Exception e) {
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
            builder.setConnectionManager(
                PoolingHttpClientConnectionManagerBuilder.create().setSSLSocketFactory(sslConfig.toSSLConnectionSocketFactory5()).build()
            );
        }

        return builder.build();
    }

}
