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

import java.security.KeyStore;
import java.util.Arrays;

import org.opensearch.security.ssl.config.KeyStoreUtils;

import org.ldaptive.ssl.CredentialConfig;
import org.ldaptive.ssl.CredentialConfigFactory;

/**
 * Builds the ldaptive {@link CredentialConfig} for the LDAP backends' trust store and client key store.
 *
 * <p>Given aliases, ldaptive copies the selected entries into a new store that it creates through
 * {@code KeyStore.Builder}, which loads it with a {@code KeyStore.SimpleLoadStoreParameter}. BCFKS rejects that
 * parameter, so in FIPS mode any alias would fail the connection. The stores are therefore narrowed to the configured
 * aliases with {@link KeyStoreUtils} first, and ldaptive gets them without aliases.
 */
public final class LdapCredentialConfig {

    private LdapCredentialConfig() {}

    /**
     * @param trustStoreAliases trusted certificate aliases, or {@code null} to trust every certificate of {@code trustStore}
     * @param keyAlias          alias of the client key ({@code cert_alias}), or {@code null} to offer every key of {@code keyStore}
     */
    public static CredentialConfig of(
        KeyStore trustStore,
        String[] trustStoreAliases,
        KeyStore keyStore,
        String keyStorePassword,
        String keyAlias
    ) {
        KeyStore trusted = trustStore == null || trustStoreAliases == null
            ? trustStore
            : KeyStoreUtils.copyAliases(trustStore, trustStore.getType(), Arrays.asList(trustStoreAliases), "the LDAP trust store");
        KeyStore keys = keyStore == null || keyAlias == null
            ? keyStore
            : KeyStoreUtils.copyKeyAlias(
                keyStore,
                keyStore.getType(),
                keyAlias,
                keyStorePassword == null ? null : keyStorePassword.toCharArray(),
                "the LDAP client key store"
            );
        return CredentialConfigFactory.createKeyStoreCredentialConfig(trusted, null, keys, keyStorePassword, null);
    }
}
