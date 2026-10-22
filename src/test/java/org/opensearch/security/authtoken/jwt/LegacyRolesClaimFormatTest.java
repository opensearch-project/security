/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.authtoken.jwt;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.function.BooleanSupplier;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Test;

import org.opensearch.Version;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.transport.TransportAddress;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

/**
 * The pre-upgrade AES/ECB roles claim as {@link EncryptionDecryptionUtil} reads and writes it during a rolling
 * upgrade.
 */
public class LegacyRolesClaimFormatTest {

    static final String encodedKey = EncryptionDecryptionUtilsTest.encodedKey;

    @Test
    public void testDecryptsLegacyEcbFormat() {
        String data = "Hello, OpenSearch!";
        String legacyEncrypted = encryptWithLegacyEcb(encodedKey, data);

        EncryptionDecryptionUtil util = new EncryptionDecryptionUtil(encodedKey, legacyFormatInUse(true));

        assertThat(util.decrypt(legacyEncrypted), is(data));
    }

    @Test
    public void testReadsBothFormatsWhileTheWindowIsOpen() {
        EncryptionDecryptionUtil duringUpgrade = new EncryptionDecryptionUtil(encodedKey, legacyFormatInUse(true));
        EncryptionDecryptionUtil afterUpgrade = new EncryptionDecryptionUtil(encodedKey, legacyFormatInUse(false));

        // What an already upgraded node issues, and what a node still in the window issues.
        assertThat(duringUpgrade.decrypt(afterUpgrade.encrypt("current roles")), is("current roles"));
        assertThat(duringUpgrade.decrypt(duringUpgrade.encrypt("legacy roles")), is("legacy roles"));
    }

    @Test
    public void testWritesLegacyFormatWhileAPreUpgradeNodeIsPresent() {
        EncryptionDecryptionUtil util = new EncryptionDecryptionUtil(encodedKey, legacyFormatInUse(true));

        String encrypted = util.encrypt("Hello, OpenSearch!");

        assertThat("a pre-upgrade node must be able to read this", encrypted, is(encryptWithLegacyEcb(encodedKey, "Hello, OpenSearch!")));
    }

    @Test
    public void testWritesCurrentFormatOnceEveryNodeIsUpgraded() {
        EncryptionDecryptionUtil util = new EncryptionDecryptionUtil(encodedKey, legacyFormatInUse(false));

        // AES-GCM is randomized, so the same input never produces the legacy value twice in a row either.
        String encrypted = util.encrypt("Hello, OpenSearch!");

        assertThat(encrypted, not(is(encryptWithLegacyEcb(encodedKey, "Hello, OpenSearch!"))));
        assertThat(util.decrypt(encrypted), is("Hello, OpenSearch!"));
    }

    @Test
    public void testStopsReadingLegacyFormatOnceTheWindowHasClosed() {
        String legacyEncrypted = encryptWithLegacyEcb(encodedKey, "Hello, OpenSearch!");

        EncryptionDecryptionUtil util = new EncryptionDecryptionUtil(encodedKey, legacyFormatInUse(false));
        RuntimeException ex = Assert.assertThrows(RuntimeException.class, () -> util.decrypt(legacyEncrypted));

        assertThat(ex.getMessage(), containsString("no longer read"));
    }

    /**
     * Wire-format check against a value this code did not produce. The ciphertext below was generated with
     * {@code printf 'role1,role2' | openssl enc -aes-128-ecb -K 30313233343536373839616263646566 -base64},
     * i.e. the first 16 bytes of the key, which is exactly what a pre-upgrade node did. It pins the format an
     * upgraded node has to keep reading, independently of the helper in this file.
     */
    @Test
    public void testDecryptsPinnedLegacyValueFromAnOlderVersion() {
        EncryptionDecryptionUtil util = new EncryptionDecryptionUtil(PINNED_KEY, legacyFormatInUse(true));

        assertThat(util.decrypt(PINNED_CIPHERTEXT), is("role1,role2"));
    }

    /**
     * The other direction against the same independent value: what this node writes for a pre-upgrade node is
     * byte for byte what OpenSSL produces, not merely what the helper in this file produces.
     */
    @Test
    public void testWritesPinnedLegacyValueForAnOlderVersion() {
        EncryptionDecryptionUtil util = new EncryptionDecryptionUtil(PINNED_KEY, legacyFormatInUse(true));

        assertThat(util.encrypt("role1,role2"), is(PINNED_CIPHERTEXT));
    }

    static final String PINNED_KEY = Base64.getEncoder()
        .encodeToString("0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8));
    static final String PINNED_CIPHERTEXT = "aJOfmltemTJ86Lsf8Z+RJQ==";

    /** A gate that reports a fixed answer, standing in for the cluster's composition. */
    static BooleanSupplier legacyFormatInUse(final boolean inUse) {
        return () -> inUse;
    }

    /**
     * Reproduces how a node running an earlier version encrypted the roles claim, with the very call it used:
     * {@code Cipher.getInstance("AES")}, the provider default, keyed with the first 16 bytes of the raw secret.
     * Deliberately not the spelled-out transformation of {@link LegacyRolesClaimFormat}, so that comparing the
     * two also checks that they agree under the provider the test runs with.
     */
    public static String encryptWithLegacyEcb(final String secret, final String data) {
        try {
            byte[] decodedKey = Base64.getDecoder().decode(secret);
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Arrays.copyOf(decodedKey, 16), "AES"));
            return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        } catch (final Exception e) {
            throw new RuntimeException("Could not build a legacy-format value for the test", e);
        }
    }

    @Test
    public void testNodeAttributeMarksThisNode() {
        Settings attribute = LegacyRolesClaimFormat.nodeAttributeSettings(Settings.EMPTY);

        assertThat(attribute.get("node.attr." + LegacyRolesClaimFormat.INTERNAL_AES_GCM_NODE_ATTRIBUTE), is("true"));
    }

    @Test
    public void testNodeAttributeToleratesItsOwnValue() {
        // e.g. node settings that already went through the plugin's additional settings once
        Settings nodeSettings = Settings.builder().put("node.attr." + LegacyRolesClaimFormat.INTERNAL_AES_GCM_NODE_ATTRIBUTE, true).build();

        assertThat(LegacyRolesClaimFormat.nodeAttributeSettings(nodeSettings).size(), is(1));
    }

    @Test
    public void testNodeAttributeCannotBeConfigured() {
        Settings nodeSettings = Settings.builder()
            .put("node.attr." + LegacyRolesClaimFormat.INTERNAL_AES_GCM_NODE_ATTRIBUTE, false)
            .build();

        IllegalArgumentException ex = Assert.assertThrows(
            IllegalArgumentException.class,
            () -> LegacyRolesClaimFormat.nodeAttributeSettings(nodeSettings)
        );
        assertThat(ex.getMessage(), containsString("must not be configured"));
    }

    @Test
    public void testANodeWithoutTheAttributeIsAPreUpgradeNode() {
        assertThat(LegacyRolesClaimFormat.hasPreUpgradeNode(cluster(true)), is(true));
        assertThat(LegacyRolesClaimFormat.hasPreUpgradeNode(cluster(false)), is(false));
    }

    @Test
    public void testIssuanceGateTreatsAnUnknownClusterAsUpgraded() {
        assertThat(LegacyRolesClaimFormat.issuanceGate(() -> null).getAsBoolean(), is(false));
        assertThat(LegacyRolesClaimFormat.issuanceGate(() -> cluster(true)).getAsBoolean(), is(true));
        assertThat(LegacyRolesClaimFormat.issuanceGate(() -> cluster(false)).getAsBoolean(), is(false));
    }

    /**
     * An upgraded node, which advertises the attribute, plus a pre-upgrade node without it if asked for. The
     * versions are deliberately the same: the gates must not look at them.
     */
    public static DiscoveryNodes cluster(final boolean withPreUpgradeNode) {
        DiscoveryNodes.Builder nodes = DiscoveryNodes.builder()
            .add(node("upgraded", 9300, Map.of(LegacyRolesClaimFormat.INTERNAL_AES_GCM_NODE_ATTRIBUTE, "true")));
        if (withPreUpgradeNode) {
            nodes.add(node("pre-upgrade", 9301, Map.of()));
        }
        return nodes.build();
    }

    private static DiscoveryNode node(final String id, final int port, final Map<String, String> attributes) {
        return new DiscoveryNode(id, new TransportAddress(TransportAddress.META_ADDRESS, port), attributes, Set.of(), Version.CURRENT);
    }
}
