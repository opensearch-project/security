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

import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;

import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.util.BCFipsEntropyDaemonFilter;
import org.opensearch.test.BouncyCastleThreadFilter;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThrows;

@RunWith(RandomizedRunner.class)
@ThreadLeakFilters(filters = { BouncyCastleThreadFilter.class, BCFipsEntropyDaemonFilter.class })
public class PemKeyReaderLoadSecretKeyTest {

    private static final SecretKey SECRET_KEY = new SecretKeySpec(
        "unit-test-hmac-key-256-bits!!!!!".getBytes(StandardCharsets.US_ASCII),
        "HmacSHA256"
    );

    @Rule
    public TemporaryFolder tempDir = new TemporaryFolder();

    @Test
    public void loadsSecretKeyByAlias() throws Exception {
        FileHelper.TypedStore typedStore = FileHelper.storeSecretKey(tempDir, "test-key", SECRET_KEY, "kspass", "keypass");
        SecretKey loaded = PemKeyReader.loadSecretKeyFromKeystore(
            typedStore.path().toString(),
            "kspass",
            typedStore.type(),
            "test-key",
            "keypass"
        );
        assertThat(loaded, notNullValue());
        assertThat(loaded.getEncoded(), equalTo(SECRET_KEY.getEncoded()));
    }

    @Test
    public void keyPasswordFallsBackToKeystorePassword() throws Exception {
        FileHelper.TypedStore typedStore = FileHelper.storeSecretKey(tempDir, "test-key", SECRET_KEY, "kspass", "kspass");
        SecretKey loaded = PemKeyReader.loadSecretKeyFromKeystore(
            typedStore.path().toString(),
            "kspass",
            typedStore.type(),
            "test-key",
            null
        );
        assertThat(loaded.getEncoded(), equalTo(SECRET_KEY.getEncoded()));
    }

    @Test
    public void throwsWhenPathIsNull() {
        var storeType = FileHelper.randomKeyStoreType();
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
        FileHelper.TypedStore typedStore = FileHelper.storeSecretKey(tempDir, "test-key", SECRET_KEY, "kspass", "keypass");
        IllegalArgumentException ex = assertThrows(
            IllegalArgumentException.class,
            () -> PemKeyReader.loadSecretKeyFromKeystore(
                typedStore.path().toString(),
                "kspass",
                typedStore.type(),
                "no-such-alias",
                "keypass"
            )
        );
        assertThat(ex.getMessage(), containsString("No key found at alias"));
        assertThat(ex.getMessage(), containsString("no-such-alias"));
    }

    @Test
    public void throwsForWrongKeystorePassword() throws Exception {
        FileHelper.TypedStore typedStore = FileHelper.storeSecretKey(tempDir, "test-key", SECRET_KEY, "kspass", "keypass");
        IllegalArgumentException ex = assertThrows(
            IllegalArgumentException.class,
            () -> PemKeyReader.loadSecretKeyFromKeystore(
                typedStore.path().toString(),
                "wrongkspass",
                typedStore.type(),
                "test-key",
                "keypass"
            )
        );
        assertThat(ex.getMessage(), containsString("Failed to load secret key from keystore-type "));
        assertThat(ex.getMessage(), containsString(typedStore.type()));
        assertThat(ex.getMessage(), containsString(typedStore.path().toString()));
    }

    @Test
    public void throwsForWrongKeyPassword() throws Exception {
        FileHelper.TypedStore typedStore = FileHelper.storeSecretKey(tempDir, "test-key", SECRET_KEY, "kspass", "keypass");
        IllegalArgumentException ex = assertThrows(
            IllegalArgumentException.class,
            () -> PemKeyReader.loadSecretKeyFromKeystore(
                typedStore.path().toString(),
                "kspass",
                typedStore.type(),
                "test-key",
                "wrongkeypass"
            )
        );
        assertThat(ex.getMessage(), containsString("Failed to load secret key from keystore-type "));
        assertThat(ex.getMessage(), containsString(typedStore.type()));
        assertThat(ex.getMessage(), containsString(typedStore.path().toString()));
    }

    @Test
    public void autoDetectsStoreTypeFromFileContentWhenTypeIsNull() throws Exception {
        FileHelper.TypedStore typedStore = FileHelper.storeSecretKey(tempDir, "test-key", SECRET_KEY, "kspass", "keypass");
        SecretKey loaded = PemKeyReader.loadSecretKeyFromKeystore(typedStore.path().toString(), "kspass", null, "test-key", "keypass");
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
}
