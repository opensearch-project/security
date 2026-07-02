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

package org.opensearch.security.util;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import org.opensearch.common.settings.Settings;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.opensearch.security.util.KeyUtils.KEYSTORE_ALIAS;
import static org.opensearch.security.util.KeyUtils.KEYSTORE_KEY_PASSWORD;
import static org.opensearch.security.util.KeyUtils.KEYSTORE_PASSWORD;
import static org.opensearch.security.util.KeyUtils.KEYSTORE_PATH;
import static org.opensearch.security.util.KeyUtils.KEYSTORE_TYPE;

public class KeyUtilsLoadKeyFromKeystoreTest {

    private static final String PREFIX = "signing_key";
    private static final SecretKey SECRET_KEY = new SecretKeySpec(
        "unit-test-hmac-key-256-bits!!!!!".getBytes(StandardCharsets.US_ASCII),
        "HmacSHA256"
    );

    @Rule
    public TemporaryFolder tempDir = new TemporaryFolder();

    @Test
    public void returnsNullWhenAliasSettingAbsent() {
        Settings settings = Settings.builder().build();
        assertThat(KeyUtils.loadKeyFromKeystore(settings, PREFIX, tempDir.getRoot().toPath()), nullValue());
    }

    @Test
    public void loadsKeyWhenAllSettingsPresent() throws Exception {
        File ks = keystoreWithKey("bcfks");
        Settings settings = Settings.builder()
            .put(PREFIX + KEYSTORE_PATH, ks.getAbsolutePath())
            .put(PREFIX + KEYSTORE_TYPE, "bcfks")
            .put(PREFIX + KEYSTORE_PASSWORD, "kspass")
            .put(PREFIX + KEYSTORE_ALIAS, "test-key")
            .put(PREFIX + KEYSTORE_KEY_PASSWORD, "keypass")
            .build();
        SecretKey loaded = KeyUtils.loadKeyFromKeystore(settings, PREFIX, tempDir.getRoot().toPath());
        assertThat(loaded, notNullValue());
        assertThat(loaded.getEncoded(), equalTo(SECRET_KEY.getEncoded()));
    }

    private File keystoreWithKey(String storeType) throws Exception {
        File file = tempDir.newFile("test." + storeType.toLowerCase());
        KeyStore ks = KeyStore.getInstance(storeType);
        ks.load(null, null);
        ks.setKeyEntry("test-key", SECRET_KEY, "keypass".toCharArray(), null);
        try (FileOutputStream fos = new FileOutputStream(file)) {
            ks.store(fos, "kspass".toCharArray());
        }
        return file;
    }
}
