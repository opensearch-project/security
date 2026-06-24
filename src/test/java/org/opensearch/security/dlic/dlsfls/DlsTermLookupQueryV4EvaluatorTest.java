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

package org.opensearch.security.dlic.dlsfls;

import org.junit.Ignore;
import org.junit.Test;

/**
 * Runs all TLQ tests with the V4 (nextgen) privilege evaluator.
 * The V4 evaluator does not have the DNFOF_MATCHER that silently absorbs
 * missing privileges on internal sub-requests, so this exercises the
 * DocumentAllowList bypass path more rigorously.
 */
public class DlsTermLookupQueryV4EvaluatorTest extends DlsTermLookupQueryTest {

    @Override
    protected String getSecurityConfigName() {
        return "securityconfig_tlq_v4.yml";
    }

    @Override
    @Test
    @Ignore("expected to fail with V4 evaluator")
    public void testMGet_1337() throws Exception {
        // V4 evaluator does not silently strip unauthorized indices from explicit _mget requests.
        // Legacy uses DNFOF_MATCHER on "indices:data/read/*" to reduce indices; V4 only reduces
        // for wildcard/pattern requests or ignore_unavailable=true. Concrete unauthorized index -> 403.
        super.testMGet_1337();
    }
}
