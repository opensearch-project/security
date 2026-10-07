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

package org.opensearch.security.authtoken.jwt;

import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;

import org.opensearch.common.settings.MockSecureSettings;
import org.opensearch.common.settings.SecureSetting;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.util.BCFipsEntropyDaemonFilter;
import org.opensearch.test.BouncyCastleThreadFilter;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

@RunWith(RandomizedRunner.class)
@ThreadLeakFilters(filters = { BouncyCastleThreadFilter.class, BCFipsEntropyDaemonFilter.class })
public class OnBehalfOfKeysTest {

    private static final String SIGNING_PREFIX = "plugins.security.on_behalf_of.signing_key.";
    private static final String ENCRYPTION_PREFIX = "plugins.security.on_behalf_of.encryption_key.";
    private static final String STORE_PASSWORD = "kspass-for-obo-tests";
    private static final String KEY_PASSWORD = "keypass-for-obo-tests";

    @Rule
    public TemporaryFolder tempDir = new TemporaryFolder();

    @Test
    public void testNothingConfiguredYieldsNoKeys() {
        final OnBehalfOfKeys keys = OnBehalfOfKeys.load(Settings.EMPTY, tempDir.getRoot().toPath());

        assertThat(keys.signingKey(), nullValue());
        assertThat(keys.encryptionKey(), nullValue());
    }

    @Test
    public void testLoadsBothKeysWithPasswordsFromSecureSettings() throws Exception {
        final byte[] signingKeyBytes = filled(64, (byte) 1);
        final byte[] encryptionKeyBytes = filled(32, (byte) 2);
        final FileHelper.TypedStore signingStore = store("obo-signing", new SecretKeySpec(signingKeyBytes, "HmacSHA512"));
        final FileHelper.TypedStore encryptionStore = store("obo-enc", new SecretKeySpec(encryptionKeyBytes, "AES"));

        final MockSecureSettings secureSettings = new MockSecureSettings();
        secureSettings.setString(SIGNING_PREFIX + "keystore_password", STORE_PASSWORD);
        secureSettings.setString(SIGNING_PREFIX + "keystore_keypassword", KEY_PASSWORD);
        secureSettings.setString(ENCRYPTION_PREFIX + "keystore_password", STORE_PASSWORD);
        secureSettings.setString(ENCRYPTION_PREFIX + "keystore_keypassword", KEY_PASSWORD);
        final Settings settings = Settings.builder()
            .put(SIGNING_PREFIX + "keystore_filepath", signingStore.path())
            .put(SIGNING_PREFIX + "keystore_type", signingStore.type())
            .put(SIGNING_PREFIX + "keystore_alias", "obo-signing")
            .put(ENCRYPTION_PREFIX + "keystore_filepath", encryptionStore.path())
            .put(ENCRYPTION_PREFIX + "keystore_type", encryptionStore.type())
            .put(ENCRYPTION_PREFIX + "keystore_alias", "obo-enc")
            .setSecureSettings(secureSettings)
            .build();

        final OnBehalfOfKeys keys = OnBehalfOfKeys.load(settings, tempDir.getRoot().toPath());

        assertThat(keys.signingKey().getEncoded(), equalTo(signingKeyBytes));
        assertThat(keys.encryptionKey().getEncoded(), equalTo(encryptionKeyBytes));
    }

    @Test
    public void testRelativePathResolvesAgainstConfigDirectory() throws Exception {
        final byte[] keyBytes = filled(64, (byte) 3);
        final FileHelper.TypedStore typedStore = store("obo-signing", new SecretKeySpec(keyBytes, "HmacSHA512"));

        final Settings settings = signingKeySettings(typedStore.path().getFileName().toString(), typedStore.type(), "obo-signing");

        final OnBehalfOfKeys keys = OnBehalfOfKeys.load(settings, tempDir.getRoot().toPath());

        assertThat(keys.signingKey().getEncoded(), equalTo(keyBytes));
        assertThat(keys.encryptionKey(), nullValue());
    }

    @Test
    public void testUnknownAliasFailsNamingTheSettings() throws Exception {
        final FileHelper.TypedStore typedStore = store("obo-signing", new SecretKeySpec(filled(64, (byte) 4), "HmacSHA512"));

        final Settings settings = signingKeySettings(typedStore.path().toString(), typedStore.type(), "no-such-alias");

        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () -> OnBehalfOfKeys.load(settings, tempDir.getRoot().toPath())
        );
        assertThat(e.getMessage(), containsString(SIGNING_PREFIX));
        assertThat(e.getMessage(), containsString("no-such-alias"));
    }

    @Test
    public void testWrongPasswordFailsWithoutRevealingIt() throws Exception {
        final FileHelper.TypedStore typedStore = store("obo-signing", new SecretKeySpec(filled(64, (byte) 5), "HmacSHA512"));

        final MockSecureSettings secureSettings = new MockSecureSettings();
        secureSettings.setString(SIGNING_PREFIX + "keystore_password", "wrong-password-value");
        final Settings settings = Settings.builder()
            .put(SIGNING_PREFIX + "keystore_filepath", typedStore.path())
            .put(SIGNING_PREFIX + "keystore_type", typedStore.type())
            .put(SIGNING_PREFIX + "keystore_alias", "obo-signing")
            .setSecureSettings(secureSettings)
            .build();

        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () -> OnBehalfOfKeys.load(settings, tempDir.getRoot().toPath())
        );
        assertThat(e.getMessage(), containsString(SIGNING_PREFIX));
        assertThat(e.getMessage(), not(containsString("wrong-password-value")));
    }

    @Test
    public void testKeyPasswordFallsBackToKeystorePassword() throws Exception {
        final byte[] keyBytes = filled(64, (byte) 8);
        final FileHelper.TypedStore typedStore = FileHelper.storeSecretKey(
            tempDir,
            "obo-signing",
            new SecretKeySpec(keyBytes, "HmacSHA512"),
            STORE_PASSWORD,
            STORE_PASSWORD
        );

        final MockSecureSettings secureSettings = new MockSecureSettings();
        secureSettings.setString(SIGNING_PREFIX + "keystore_password", STORE_PASSWORD);
        final Settings settings = Settings.builder()
            .put(SIGNING_PREFIX + "keystore_filepath", typedStore.path())
            .put(SIGNING_PREFIX + "keystore_type", typedStore.type())
            .put(SIGNING_PREFIX + "keystore_alias", "obo-signing")
            .setSecureSettings(secureSettings)
            .build();

        assertThat(OnBehalfOfKeys.load(settings, tempDir.getRoot().toPath()).signingKey().getEncoded(), equalTo(keyBytes));
    }

    @Test
    public void testWrongKeyPasswordFailsNamingTheSettings() throws Exception {
        final FileHelper.TypedStore typedStore = store("obo-signing", new SecretKeySpec(filled(64, (byte) 9), "HmacSHA512"));

        final MockSecureSettings secureSettings = new MockSecureSettings();
        secureSettings.setString(SIGNING_PREFIX + "keystore_password", STORE_PASSWORD);
        secureSettings.setString(SIGNING_PREFIX + "keystore_keypassword", "wrong-key-password");
        final Settings settings = Settings.builder()
            .put(SIGNING_PREFIX + "keystore_filepath", typedStore.path())
            .put(SIGNING_PREFIX + "keystore_type", typedStore.type())
            .put(SIGNING_PREFIX + "keystore_alias", "obo-signing")
            .setSecureSettings(secureSettings)
            .build();

        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () -> OnBehalfOfKeys.load(settings, tempDir.getRoot().toPath())
        );
        assertThat(e.getMessage(), containsString(SIGNING_PREFIX));
        assertThat(e.getMessage(), not(containsString("wrong-key-password")));
    }

    @Test
    public void testStoreTypeIsDetectedWhenNotConfigured() throws Exception {
        final byte[] keyBytes = filled(64, (byte) 10);
        final FileHelper.TypedStore typedStore = store("obo-signing", new SecretKeySpec(keyBytes, "HmacSHA512"));

        final MockSecureSettings secureSettings = new MockSecureSettings();
        secureSettings.setString(SIGNING_PREFIX + "keystore_password", STORE_PASSWORD);
        secureSettings.setString(SIGNING_PREFIX + "keystore_keypassword", KEY_PASSWORD);
        final Settings settings = Settings.builder()
            .put(SIGNING_PREFIX + "keystore_filepath", typedStore.path())
            .put(SIGNING_PREFIX + "keystore_alias", "obo-signing")
            .setSecureSettings(secureSettings)
            .build();

        assertThat(OnBehalfOfKeys.load(settings, tempDir.getRoot().toPath()).signingKey().getEncoded(), equalTo(keyBytes));
    }

    @Test
    public void testKeystoreWithoutAliasIsRejected() {
        final Settings settings = Settings.builder().put(SIGNING_PREFIX + "keystore_filepath", "obo.bcfks").build();

        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () -> OnBehalfOfKeys.load(settings, tempDir.getRoot().toPath())
        );
        assertThat(e.getMessage(), containsString(SIGNING_PREFIX + "keystore_alias is required"));
    }

    @Test
    public void testPasswordAloneCountsAsConfiguredAndIsRejected() {
        final MockSecureSettings secureSettings = new MockSecureSettings();
        secureSettings.setString(SIGNING_PREFIX + "keystore_password", STORE_PASSWORD);
        final Settings settings = Settings.builder().setSecureSettings(secureSettings).build();

        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () -> OnBehalfOfKeys.load(settings, tempDir.getRoot().toPath())
        );
        assertThat(e.getMessage(), containsString(SIGNING_PREFIX + "keystore_alias is required"));
    }

    @Test
    public void testEmptyAliasIsAValidAlias() throws Exception {
        final byte[] keyBytes = filled(64, (byte) 7);
        final FileHelper.TypedStore typedStore = store("", new SecretKeySpec(keyBytes, "HmacSHA512"));

        final Settings settings = signingKeySettings(typedStore.path().toString(), typedStore.type(), "");

        assertThat(OnBehalfOfKeys.load(settings, tempDir.getRoot().toPath()).signingKey().getEncoded(), equalTo(keyBytes));
    }

    @Test
    public void testFileBasedKeystoreWithoutPathIsRejected() {
        final Settings settings = Settings.builder()
            .put(ENCRYPTION_PREFIX + "keystore_type", "BCFKS")
            .put(ENCRYPTION_PREFIX + "keystore_alias", "obo-enc")
            .build();

        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () -> OnBehalfOfKeys.load(settings, tempDir.getRoot().toPath())
        );
        assertThat(e.getMessage(), containsString(ENCRYPTION_PREFIX + "keystore_filepath is required"));
    }

    @Test
    public void testPasswordInOpensearchYmlIsRejected() {
        final Settings settings = Settings.builder()
            .put(SIGNING_PREFIX + "keystore_filepath", "obo.bcfks")
            .put(SIGNING_PREFIX + "keystore_alias", "obo-signing")
            .put(SIGNING_PREFIX + "keystore_password", STORE_PASSWORD)
            .build();

        final IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class,
            () -> OnBehalfOfKeys.load(settings, tempDir.getRoot().toPath())
        );
        assertThat(e.getMessage(), containsString("secure setting"));
    }

    @Test
    public void testPasswordsAreSecureSettingsAndTheRestIsFiltered() {
        for (final Setting<?> setting : OnBehalfOfKeys.getSettings()) {
            if (setting.getKey().endsWith("password")) {
                assertThat(setting.getKey(), setting, instanceOf(SecureSetting.class));
            } else {
                assertTrue(setting.getKey(), setting.isFiltered());
                assertThat(setting.getKey(), setting.hasNodeScope(), is(true));
            }
        }
    }

    @Test
    public void testToStringRedactsKeys() {
        final OnBehalfOfKeys keys = new OnBehalfOfKeys(new SecretKeySpec(filled(64, (byte) 6), "HmacSHA512"), null);

        assertThat(keys.toString(), equalTo("OnBehalfOfKeys[signingKey=****, encryptionKey=<not set>]"));
    }

    private FileHelper.TypedStore store(final String alias, final SecretKeySpec key) throws Exception {
        return FileHelper.storeSecretKey(tempDir, alias, key, STORE_PASSWORD, KEY_PASSWORD);
    }

    private static Settings signingKeySettings(final String filepath, final String type, final String alias) {
        final MockSecureSettings secureSettings = new MockSecureSettings();
        secureSettings.setString(SIGNING_PREFIX + "keystore_password", STORE_PASSWORD);
        secureSettings.setString(SIGNING_PREFIX + "keystore_keypassword", KEY_PASSWORD);
        return Settings.builder()
            .put(SIGNING_PREFIX + "keystore_filepath", filepath)
            .put(SIGNING_PREFIX + "keystore_type", type)
            .put(SIGNING_PREFIX + "keystore_alias", alias)
            .setSecureSettings(secureSettings)
            .build();
    }

    private static byte[] filled(final int length, final byte value) {
        final byte[] bytes = new byte[length];
        Arrays.fill(bytes, value);
        return bytes;
    }
}
