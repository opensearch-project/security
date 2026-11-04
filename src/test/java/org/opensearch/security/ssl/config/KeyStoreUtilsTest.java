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

package org.opensearch.security.ssl.config;

import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.crypto.spec.SecretKeySpec;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;

import org.opensearch.OpenSearchException;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.util.BCFipsEntropyDaemonFilter;
import org.opensearch.test.BouncyCastleThreadFilter;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThrows;

@RunWith(RandomizedRunner.class)
@ThreadLeakFilters(filters = { BouncyCastleThreadFilter.class, BCFipsEntropyDaemonFilter.class })
public class KeyStoreUtilsTest {

    private static final char[] STORE_PASSWORD = "kspass-for-keystore-utils".toCharArray();
    private static final char[] KEY_PASSWORD = "keypass-for-keystore-utils".toCharArray();

    @Rule
    public TemporaryFolder tempDir = new TemporaryFolder();

    @Test
    public void testLoadSecretKey() throws Exception {
        final byte[] keyBytes = new byte[32];
        Arrays.fill(keyBytes, (byte) 3);
        final KeyStore store = storeWith("secret", new SecretKeySpec(keyBytes, "AES"));

        assertThat(KeyStoreUtils.loadSecretKey(store, "secret", KEY_PASSWORD).getEncoded(), equalTo(keyBytes));
    }

    @Test
    public void testLoadSecretKeyWithUnknownAlias() throws Exception {
        final KeyStore store = storeWith("secret", new SecretKeySpec(new byte[32], "AES"));

        final OpenSearchException e = assertThrows(
            OpenSearchException.class,
            () -> KeyStoreUtils.loadSecretKey(store, "no-such-alias", KEY_PASSWORD)
        );
        assertThat(e.getMessage(), containsString("No key found at alias 'no-such-alias'"));
    }

    @Test
    public void testLoadSecretKeyWithWrongKeyPassword() throws Exception {
        final KeyStore store = storeWith("secret", new SecretKeySpec(new byte[32], "AES"));

        final OpenSearchException e = assertThrows(
            OpenSearchException.class,
            () -> KeyStoreUtils.loadSecretKey(store, "secret", "wrong-key-password".toCharArray())
        );
        assertThat(e.getMessage(), containsString("Failed to read the key at alias 'secret'"));
    }

    @Test
    public void testLoadSecretKeyRejectsPrivateKeyEntry() throws Exception {
        final Path path = Path.of(getClass().getClassLoader().getResource("kirk-keystore.bcfks").toURI());
        final KeyStore store = KeyStoreUtils.loadKeyStore(path, "BCFKS", "changeit".toCharArray());

        final OpenSearchException e = assertThrows(
            OpenSearchException.class,
            () -> KeyStoreUtils.loadSecretKey(store, "kirk", "changeit".toCharArray())
        );
        assertThat(e.getMessage(), containsString("'kirk' is not a SecretKey"));
    }

    @Test
    public void testCopyKeyAliasKeepsOnlyThatKeyInAStoreOfTheGivenType() throws Exception {
        final KeyStore store = storeWithKirkAndSpock();

        final KeyStore narrowed = KeyStoreUtils.copyKeyAlias(store, store.getType(), "spock", "changeit".toCharArray(), "test");

        assertThat(narrowed.getType(), equalTo(store.getType()));
        assertThat(Collections.list(narrowed.aliases()), equalTo(List.of("spock")));
        assertThat(narrowed.getKey("spock", "changeit".toCharArray()), equalTo(store.getKey("spock", "changeit".toCharArray())));
        assertThat(narrowed.getCertificateChain("spock"), equalTo(store.getCertificateChain("spock")));
    }

    @Test
    public void testCopyKeyAliasWithUnknownAlias() throws Exception {
        final KeyStore store = storeWithKirkAndSpock();

        final OpenSearchException e = assertThrows(
            OpenSearchException.class,
            () -> KeyStoreUtils.copyKeyAlias(store, store.getType(), "missing", "changeit".toCharArray(), "test")
        );
        assertThat(e.getMessage(), containsString("Failed to load key store from test"));
        assertThat(e.getCause().getMessage(), containsString("Couldn't find SSL key for alias missing"));
    }

    @Test
    public void testCopyAliasesKeepsOnlyThoseCertificates() throws Exception {
        final KeyStore trustStore = FileHelper.getKeystoreFromClassPath("ldap/truststore", "changeit");

        final KeyStore narrowed = KeyStoreUtils.copyAliases(trustStore, trustStore.getType(), List.of("root-ca-chain"), "test");

        assertThat(narrowed.getType(), equalTo(trustStore.getType()));
        assertThat(Collections.list(narrowed.aliases()), equalTo(List.of("root-ca-chain")));
        assertThat(narrowed.getCertificate("root-ca-chain"), equalTo(trustStore.getCertificate("root-ca-chain")));
    }

    @Test
    public void testCopyAliasesWithUnknownAlias() throws Exception {
        final KeyStore trustStore = FileHelper.getKeystoreFromClassPath("ldap/truststore", "changeit");

        final OpenSearchException e = assertThrows(
            OpenSearchException.class,
            () -> KeyStoreUtils.copyAliases(trustStore, trustStore.getType(), List.of("root-ca-chain", "missing"), "test")
        );
        assertThat(e.getCause().getMessage(), containsString("Alias missing does not contain a certificate entry"));
    }

    /** One store holding the kirk and spock client keys of the LDAP test certificates. */
    private static KeyStore storeWithKirkAndSpock() throws Exception {
        final KeyStore kirk = FileHelper.getKeystoreFromClassPath("ldap/kirk-keystore", "changeit");
        final KeyStore spock = FileHelper.getKeystoreFromClassPath("ldap/spock-keystore", "changeit");
        final KeyStore combined = KeyStore.getInstance(kirk.getType());
        combined.load(null, null);
        final KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection("changeit".toCharArray());
        combined.setEntry("kirk", kirk.getEntry("kirk", protection), protection);
        combined.setEntry("spock", spock.getEntry("spock", protection), protection);
        return combined;
    }

    private KeyStore storeWith(final String alias, final SecretKeySpec key) throws Exception {
        final FileHelper.TypedStore typedStore = FileHelper.storeSecretKey(
            tempDir,
            alias,
            key,
            new String(STORE_PASSWORD),
            new String(KEY_PASSWORD)
        );
        return KeyStoreUtils.loadKeyStore(typedStore.path(), typedStore.type(), STORE_PASSWORD);
    }
}
