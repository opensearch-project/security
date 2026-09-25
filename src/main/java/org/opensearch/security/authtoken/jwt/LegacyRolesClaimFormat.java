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

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.cluster.ClusterChangedEvent;
import org.opensearch.cluster.ClusterStateListener;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.action.onbehalf.CreateOnBehalfOfTokenAction;
import org.opensearch.security.support.FipsMode;

/**
 * Transitional: the pre-upgrade AES/ECB format of the encrypted roles claim, and when a node still has to
 * read or write it. Everything that only exists so that a cluster can be upgraded across the switch to
 * AES-GCM without invalidating on-behalf-of tokens lives here.
 *
 * <p>Tokens issued by earlier versions encrypt their roles with {@code Cipher.getInstance("AES")}, keyed with the
 * first 16 bytes of the raw secret (zero-padded if it was shorter). {@code "AES"} alone is a provider default:
 * SunJCE resolves it to AES/ECB/PKCS5Padding, BC FIPS to AES/ECB/PKCS7Padding, which produce the same bytes for
 * a 16-byte block. This class spells the transformation out, so that it does not depend on the provider.
 *
 * <p>Which nodes are upgraded is decided by capability, not by version: every node that reads AES-GCM
 * advertises {@link #INTERNAL_AES_GCM_NODE_ATTRIBUTE}, so a node without it is a pre-upgrade node, whatever release
 * this lands in or is backported to.
 *
 * <p>Remove it with the next major version, not earlier. A rolling upgrade may skip minor versions, so a
 * cluster could go from a release before this class straight to one after it, and on-behalf-of tokens would
 * then fail in both directions until the last node is upgraded. Across a major version that cannot happen,
 * because a rolling upgrade has to start from the last minor of the previous major, which contains this class.
 */
public final class LegacyRolesClaimFormat {

    private static final Logger LOG = LogManager.getLogger(LegacyRolesClaimFormat.class);

    private static final String LEGACY_AES_ECB = "AES/ECB/PKCS5Padding";
    private static final int LEGACY_KEY_LENGTH_BYTES = 16;

    /**
     * Internal node attribute a node advertises when it encrypts the roles claim with AES-GCM and reads both
     * formats. Set by the plugin, never by the operator, hence {@code internal} in its name: see
     * {@link #nodeAttributeSettings(Settings)}.
     */
    public static final String INTERNAL_AES_GCM_NODE_ATTRIBUTE = "security.internal.obo_roles_aes_gcm";

    private static final String INTERNAL_AES_GCM_NODE_ATTRIBUTE_SETTING = "node.attr." + INTERNAL_AES_GCM_NODE_ATTRIBUTE;

    // Key material for the pre-upgrade AES/ECB format. Kept in FIPS mode as well: a cluster that ran an
    // earlier version on BC FIPS still issued tokens in that format, because the module permits the ECB
    // primitive in approved-only mode. Those tokens are read during the upgrade window, never written.
    private final SecretKey key;

    // Whether the legacy format is still in play for this cluster, evaluated per call because the answer
    // changes underneath a long-lived instance as nodes are upgraded.
    private final BooleanSupplier inUse;

    private final AtomicBoolean firstTokenLogged = new AtomicBoolean();

    /**
     * Rebuilds the key the pre-upgrade code used: the raw secret truncated to 16 bytes, zero-padded when it
     * was shorter. Copies what it needs, so the caller may wipe {@code secretBytes} afterwards.
     */
    LegacyRolesClaimFormat(final byte[] secretBytes, final BooleanSupplier inUse) {
        this.key = new SecretKeySpec(Arrays.copyOf(secretBytes, LEGACY_KEY_LENGTH_BYTES), "AES");
        this.inUse = inUse;
    }

    /**
     * The node attribute this node advertises, for {@code Plugin#additionalSettings()}.
     *
     * <p>The attribute is reserved. Node settings from {@code opensearch.yml} override what a plugin adds, so
     * an operator value would silently win; anything other than the plugin's own value is therefore refused at
     * startup. This only guards upgraded nodes. On a pre-upgrade node this code does not run, and setting the
     * attribute there by hand would make upgraded nodes write AES-GCM that node cannot read.
     *
     * @throws IllegalArgumentException if the node settings configure the attribute to anything but {@code true}
     */
    public static Settings nodeAttributeSettings(final Settings nodeSettings) {
        final String configured = nodeSettings.get(INTERNAL_AES_GCM_NODE_ATTRIBUTE_SETTING);
        if (configured != null && !"true".equals(configured)) {
            throw new IllegalArgumentException(
                "["
                    + INTERNAL_AES_GCM_NODE_ATTRIBUTE_SETTING
                    + "] is internal to the security plugin, which sets it to mark nodes that read AES-GCM "
                    + "on-behalf-of tokens; it must not be configured"
            );
        }
        return Settings.builder().put(INTERNAL_AES_GCM_NODE_ATTRIBUTE_SETTING, true).build();
    }

    /**
     * True while the given nodes include one that does not advertise {@link #INTERNAL_AES_GCM_NODE_ATTRIBUTE}, i.e. a
     * node that cannot read the AES-GCM roles claim.
     */
    static boolean hasPreUpgradeNode(final DiscoveryNodes nodes) {
        for (final DiscoveryNode node : nodes) {
            if (!"true".equals(node.getAttributes().get(INTERNAL_AES_GCM_NODE_ATTRIBUTE))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Issuance gate: true while the cluster still contains a node that cannot read the AES-GCM roles claim,
     * in which case a token has to be issued in the format that node understands. Unlike verification,
     * issuance follows the cluster's composition directly: the first token issued after the last pre-upgrade
     * node leaves should already use AES-GCM. A cluster that is not known yet counts as upgraded, so an
     * unknown cluster never causes the weaker format to be written.
     */
    public static BooleanSupplier issuanceGate(final Supplier<DiscoveryNodes> nodes) {
        return () -> {
            final DiscoveryNodes current = nodes.get();
            return current != null && hasPreUpgradeNode(current);
        };
    }

    /**
     * Whether {@link EncryptionDecryptionUtil#encrypt} has to write this format instead of AES-GCM: while the
     * cluster still contains a node that cannot read AES-GCM, so that every node can read what any other
     * node issues.
     *
     * <p>Never in FIPS mode, whatever the cluster looks like, because AES/ECB is not an approved mode for
     * confidentiality (NIST SP 800-38A). A pre-upgrade node in a FIPS cluster therefore cannot read what an
     * upgraded node issues, and rejects such tokens until it is upgraded itself.
     */
    boolean writes() {
        return !FipsMode.isEnabled() && inUse.getAsBoolean();
    }

    String encrypt(final byte[] plaintext) {
        try {
            Cipher cipher = Cipher.getInstance(LEGACY_AES_ECB);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext));
        } catch (final Exception e) {
            throw new RuntimeException("Error processing data with cipher", e);
        }
    }

    /**
     * Second half of the trial decryption in {@link EncryptionDecryptionUtil#decrypt}: reads the pre-upgrade
     * AES/ECB format, independently of FIPS mode, which restricts writing that format, not reading it.
     *
     * @param tagFailure the tag mismatch that ruled out the current format, kept as the cause so that a value
     *                   which is neither format still reports why GCM rejected it
     */
    String decrypt(final byte[] decodedBytes, final AEADBadTagException tagFailure) {
        if (!inUse.getAsBoolean()) {
            throw new RuntimeException(
                "Error processing data with cipher: the value is not in the AES-GCM format, and the legacy "
                    + "AES/ECB format is no longer read because every node in this cluster reads AES-GCM and "
                    + "any token predating the upgrade has expired",
                tagFailure
            );
        }
        try {
            Cipher cipher = Cipher.getInstance(LEGACY_AES_ECB);
            cipher.init(Cipher.DECRYPT_MODE, key);
            final String plaintext = new String(cipher.doFinal(decodedBytes), StandardCharsets.UTF_8);
            if (firstTokenLogged.compareAndSet(false, true)) {
                logFirstToken();
            }
            return plaintext;
        } catch (final Exception e) {
            e.addSuppressed(tagFailure);
            throw new RuntimeException("Error processing data with cipher", e);
        }
    }

    /**
     * Reports the first pre-upgrade token this instance reads. In FIPS mode this is worth a warning rather
     * than a note: an earlier version running on BC FIPS could issue AES/ECB tokens, because the module
     * permits the primitive in approved-only mode, and reading them means operating outside what NIST
     * SP 800-38A approves for confidentiality until the upgrade window closes.
     */
    private static void logFirstToken() {
        if (FipsMode.isEnabled()) {
            LOG.warn(
                "Decrypted an on-behalf-of token in the legacy AES/ECB format, which is not an approved mode "
                    + "for confidentiality. Such tokens were issued before the upgrade and are accepted only "
                    + "until every node is upgraded and the tokens predating the upgrade have expired. Nothing "
                    + "is written in that format."
            );
            return;
        }
        LOG.info(
            "Decrypted an on-behalf-of token that still uses the legacy AES/ECB format. Such tokens were "
                + "issued by nodes running an earlier version and stop appearing once every node is upgraded "
                + "and the tokens issued before the upgrade have expired."
        );
    }

    /**
     * Decides how long this node keeps reading the pre-upgrade format. One instance per node, registered as a
     * cluster state listener; {@link #legacyFormatReadable()} is the verification gate.
     *
     * <p>Verification cannot follow the cluster's composition on its own: the moment the last pre-upgrade node
     * leaves, the tokens it issued are still valid for up to {@link CreateOnBehalfOfTokenAction#OBO_MAX_EXPIRY_SECONDS},
     * and rejecting them would reintroduce the outage the dual-format read exists to avoid. Reading therefore
     * stays open for one maximum token lifetime after the last cluster state that contained a pre-upgrade node.
     *
     * <p>That moment is taken from the cluster state as it changes, not when a token happens to be read, so a
     * node that has seen no legacy token for a while still knows when the last pre-upgrade node left. A change
     * whose previous state still held such a node counts as a sighting, which measures the window from the
     * change that removed the node, however long the cluster state was quiet before it.
     *
     * <p>A node that starts after the upgrade has no way to know what the cluster looked like before, so the
     * window starts open and closes one token lifetime after the tracker was created.
     */
    public static final class PreUpgradeNodeTracker implements ClusterStateListener {

        private final LongSupplier clock;
        // Written after preUpgradeNodeLastSeenMs, so a reader that sees a new state also sees its sighting.
        private volatile DiscoveryNodes nodes;
        private volatile long preUpgradeNodeLastSeenMs;

        public PreUpgradeNodeTracker() {
            this(System::currentTimeMillis);
        }

        PreUpgradeNodeTracker(final LongSupplier clock) {
            this.clock = clock;
            this.preUpgradeNodeLastSeenMs = clock.getAsLong();
        }

        @Override
        public void clusterChanged(final ClusterChangedEvent event) {
            final DiscoveryNodes current = event.state().nodes();
            if (hasPreUpgradeNode(event.previousState().nodes()) || hasPreUpgradeNode(current)) {
                preUpgradeNodeLastSeenMs = clock.getAsLong();
            }
            nodes = current;
        }

        /** Verification gate: whether this node still reads the pre-upgrade format. */
        public boolean legacyFormatReadable() {
            final DiscoveryNodes current = nodes;
            // Null means no cluster state has been observed yet; treat that like a cluster that may still hold
            // a pre-upgrade node, since reading too long is harmless and rejecting a valid token is not.
            if (current == null || hasPreUpgradeNode(current)) {
                return true;
            }
            return clock.getAsLong() - preUpgradeNodeLastSeenMs < TimeUnit.SECONDS.toMillis(
                CreateOnBehalfOfTokenAction.OBO_MAX_EXPIRY_SECONDS
            );
        }
    }
}
