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

import java.security.cert.X509Certificate;

import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.transport.DefaultInterClusterRequestEvaluator;
import org.opensearch.security.transport.InterClusterRequestEvaluator;
import org.opensearch.transport.TransportRequest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;

/**
 * Reproducer for the silent-fallback behavior described in
 * https://github.com/opensearch-project/security/issues/6479
 *
 * When {@code plugins.security.cert.intercluster_request_evaluator_class} points
 * at an FQCN that cannot be loaded (missing class, wrong constructor, ctor
 * throws), {@link ReflectionHelper#instantiateInterClusterRequestEvaluator}
 * currently logs a warning and silently returns a
 * {@link DefaultInterClusterRequestEvaluator}. This test pins that behavior so
 * any change to fail-fast semantics is intentional and visible in review.
 */
public class ReflectionHelperTest {

    @Test
    public void silentFallback_whenClassDoesNotExist() {
        InterClusterRequestEvaluator result = ReflectionHelper.instantiateInterClusterRequestEvaluator(
            "this.class.definitely.does.not.Exist",
            Settings.EMPTY
        );
        assertThat(result, instanceOf(DefaultInterClusterRequestEvaluator.class));
    }

    @Test
    public void silentFallback_whenSettingsConstructorMissing() {
        InterClusterRequestEvaluator result = ReflectionHelper.instantiateInterClusterRequestEvaluator(
            NoSettingsCtorEvaluator.class.getName(),
            Settings.EMPTY
        );
        assertThat(result, instanceOf(DefaultInterClusterRequestEvaluator.class));
    }

    @Test
    public void silentFallback_whenConstructorThrows() {
        InterClusterRequestEvaluator result = ReflectionHelper.instantiateInterClusterRequestEvaluator(
            ThrowingCtorEvaluator.class.getName(),
            Settings.EMPTY
        );
        assertThat(result, instanceOf(DefaultInterClusterRequestEvaluator.class));
    }

    @Test
    public void successPath_returnsRequestedImpl() {
        InterClusterRequestEvaluator result = ReflectionHelper.instantiateInterClusterRequestEvaluator(
            LoadableEvaluator.class.getName(),
            Settings.EMPTY
        );
        assertThat(result, instanceOf(LoadableEvaluator.class));
    }

    // --- fixtures ---------------------------------------------------------

    /** Implements the interface but has no (Settings) constructor -> should trigger fallback. */
    public static class NoSettingsCtorEvaluator implements InterClusterRequestEvaluator {
        public NoSettingsCtorEvaluator() {}

        @Override
        public boolean isInterClusterRequest(
            TransportRequest request,
            X509Certificate[] localCerts,
            X509Certificate[] peerCerts,
            String principal
        ) {
            return false;
        }
    }

    /** (Settings) constructor exists but throws -> should trigger fallback. */
    public static class ThrowingCtorEvaluator implements InterClusterRequestEvaluator {
        public ThrowingCtorEvaluator(Settings settings) {
            throw new IllegalStateException("boom");
        }

        @Override
        public boolean isInterClusterRequest(
            TransportRequest request,
            X509Certificate[] localCerts,
            X509Certificate[] peerCerts,
            String principal
        ) {
            return false;
        }
    }

    /** Valid loadable evaluator -> should be returned unchanged. */
    public static class LoadableEvaluator implements InterClusterRequestEvaluator {
        public LoadableEvaluator(Settings settings) {}

        @Override
        public boolean isInterClusterRequest(
            TransportRequest request,
            X509Certificate[] localCerts,
            X509Certificate[] peerCerts,
            String principal
        ) {
            return false;
        }
    }
}
