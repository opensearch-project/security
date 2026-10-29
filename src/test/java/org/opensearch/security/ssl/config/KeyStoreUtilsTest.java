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
