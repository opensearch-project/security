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

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.ThreadFilter;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;

import org.opensearch.test.BouncyCastleThreadFilter;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static com.carrotsearch.randomizedtesting.RandomizedTest.randomFrom;
import static org.junit.Assert.assertThrows;

@RunWith(RandomizedRunner.class)
@ThreadLeakFilters(filters = { BouncyCastleThreadFilter.class, PemKeyReaderLoadSecretKeyTest.BCFipsEntropyDaemonFilter.class })
public class PemKeyReaderLoadSecretKeyTest {

    // "BC FIPS Entropy Daemon" is not yet covered by the framework's BouncyCastleThreadFilter.
    public static class BCFipsEntropyDaemonFilter implements ThreadFilter {
        @Override
        public boolean reject(Thread t) {
            return "BC FIPS Entropy Daemon".equals(t.getName());
        }
    }

    private static final SecretKey SECRET_KEY = new SecretKeySpec(
        "unit-test-hmac-key-256-bits!!!!!".getBytes(StandardCharsets.US_ASCII),
        "HmacSHA256"
    );

    @Rule
    public TemporaryFolder tempDir = new TemporaryFolder();

    private String storeType;

    @Before
    public void setup() {
        storeType = randomKeyStoreType();
    }

    @Test
    public void loadsSecretKeyByAlias() throws Exception {
        File ks = storeKeystoreWithKey("test-key", SECRET_KEY, "kspass", "keypass", storeType);
        SecretKey loaded = PemKeyReader.loadSecretKeyFromKeystore(ks.getAbsolutePath(), "kspass", storeType, "test-key", "keypass");
        assertThat(loaded, notNullValue());
        assertThat(loaded.getEncoded(), equalTo(SECRET_KEY.getEncoded()));
    }

    @Test
    public void keyPasswordFallsBackToKeystorePassword() throws Exception {
        File ks = storeKeystoreWithKey("test-key", SECRET_KEY, "kspass", "kspass", storeType);
        SecretKey loaded = PemKeyReader.loadSecretKeyFromKeystore(ks.getAbsolutePath(), "kspass", storeType, "test-key", null);
        assertThat(loaded.getEncoded(), equalTo(SECRET_KEY.getEncoded()));
    }

    @Test
    public void throwsWhenPathIsNull() {
        IllegalArgumentException ex = assertThrows(
            IllegalArgumentException.class,
            () -> PemKeyReader.loadSecretKeyFromKeystore(null, "kspass", storeType, "test-key", "keypass")
        );
        assertThat(ex.getMessage(), containsString("Failed to load secret key from keystore-type "));
        assertThat(ex.getMessage(), containsString(storeType));
        assertThat(ex.getMessage(), containsString("at path 'null'"));
    }

    @Test
    public void throwsForNonexistentAlias() throws Exception {
        File ks = storeKeystoreWithKey("test-key", SECRET_KEY, "kspass", "keypass", storeType);
        IllegalArgumentException ex = assertThrows(
            IllegalArgumentException.class,
            () -> PemKeyReader.loadSecretKeyFromKeystore(ks.getAbsolutePath(), "kspass", storeType, "no-such-alias", "keypass")
        );
        assertThat(ex.getMessage(), containsString("No key found at alias"));
        assertThat(ex.getMessage(), containsString("no-such-alias"));
    }

    @Test
    public void throwsForWrongKeystorePassword() throws Exception {
        File ks = storeKeystoreWithKey("test-key", SECRET_KEY, "kspass", "keypass", storeType);
        IllegalArgumentException ex = assertThrows(
            IllegalArgumentException.class,
            () -> PemKeyReader.loadSecretKeyFromKeystore(ks.getAbsolutePath(), "wrongkspass", storeType, "test-key", "keypass")
        );
        assertThat(ex.getMessage(), containsString("Failed to load secret key from keystore-type "));
        assertThat(ex.getMessage(), containsString(storeType));
        assertThat(ex.getMessage(), containsString(ks.getAbsolutePath()));
    }

    @Test
    public void throwsForWrongKeyPassword() throws Exception {
        File ks = storeKeystoreWithKey("test-key", SECRET_KEY, "kspass", "keypass", storeType);
        IllegalArgumentException ex = assertThrows(
            IllegalArgumentException.class,
            () -> PemKeyReader.loadSecretKeyFromKeystore(ks.getAbsolutePath(), "kspass", storeType, "test-key", "wrongkeypass")
        );
        assertThat(ex.getMessage(), containsString("Failed to load secret key from keystore-type "));
        assertThat(ex.getMessage(), containsString(storeType));
        assertThat(ex.getMessage(), containsString(ks.getAbsolutePath()));
    }

    @Test
    public void autoDetectsStoreTypeFromFileContentWhenTypeIsNull() throws Exception {
        File ks = storeKeystoreWithKey("test-key", SECRET_KEY, "kspass", "keypass", storeType);
        SecretKey loaded = PemKeyReader.loadSecretKeyFromKeystore(ks.getAbsolutePath(), "kspass", null, "test-key", "keypass");
        assertThat(loaded, notNullValue());
        assertThat(loaded.getEncoded(), equalTo(SECRET_KEY.getEncoded()));
    }

    @Test
    public void throwsWhenAliasHoldsNonSecretKey() {
        String ksPath = getClass().getClassLoader().getResource("kirk-keystore.bcfks").getPath();
        IllegalArgumentException ex = assertThrows(
            IllegalArgumentException.class,
            () -> PemKeyReader.loadSecretKeyFromKeystore(ksPath, "changeit", "BCFKS", "kirk", "changeit")
        );
        assertThat(ex.getMessage(), containsString("kirk"));
        assertThat(ex.getMessage(), containsString("is not a SecretKey"));
    }

    private File storeKeystoreWithKey(String alias, SecretKey key, String ksPassword, String keyPassword, String storeType)
        throws Exception {
        File file = tempDir.newFile("test." + storeType.toLowerCase());
        KeyStore ks = KeyStore.getInstance(storeType);
        ks.load(null, null);
        ks.setKeyEntry(alias, key, keyPassword.toCharArray(), null);
        try (FileOutputStream fos = new FileOutputStream(file)) {
            ks.store(fos, ksPassword.toCharArray());
        }
        return file;
    }

    private String randomKeyStoreType() {
        // JKS is excluded: its engineSetKeyEntry enforces instanceof PrivateKey (the asymmetric-key
        // interface), so SecretKey entries are rejected with "Cannot store non-PrivateKeys".
        // JCEKS was introduced specifically to extend JKS with SecretKey support.
        // BCFKS (BC FIPS) also supports SecretKey and is the only FIPS-approved option.
        return FipsMode.isEnabled() //
            ? randomFrom(new String[] { "bcfks" }) //
            : randomFrom(new String[] { "bcfks", "jceks", "pkcs12" });
    }
}
