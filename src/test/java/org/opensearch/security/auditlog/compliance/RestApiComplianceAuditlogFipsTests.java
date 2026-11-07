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

package org.opensearch.security.auditlog.compliance;

import org.junit.Ignore;
import org.junit.Test;

/**
 * FIPS variant of {@link RestApiComplianceAuditlogTest}. Argon2 is still not FIPS-approved, so the
 * case checking that its hashes are redacted from the audit log cannot run.
 */
public class RestApiComplianceAuditlogFipsTests extends RestApiComplianceAuditlogTest {

    @Override
    @Test
    @Ignore("Argon2 is not supported in FIPS mode")
    public void testArgon2HashRedaction() {}
}
