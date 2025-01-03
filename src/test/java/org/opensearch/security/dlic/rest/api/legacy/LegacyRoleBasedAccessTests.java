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

package org.opensearch.security.dlic.rest.api.legacy;

import java.util.Arrays;
import java.util.Collection;

import com.carrotsearch.randomizedtesting.annotations.Name;
import com.carrotsearch.randomizedtesting.annotations.ParametersFactory;

import org.opensearch.security.dlic.rest.api.RoleBasedAccessTest;

import static org.opensearch.security.OpenSearchSecurityPlugin.LEGACY_OPENDISTRO_PREFIX;

public class LegacyRoleBasedAccessTests extends RoleBasedAccessTest {

    @ParametersFactory()
    public static Collection<Object[]> params() {
        return Arrays.asList(new Object[] { false }, new Object[] { true });
    }

    public LegacyRoleBasedAccessTests(@Name("useOldPrivilegeEvaluationImplementation") boolean useOldPrivilegeEvaluationImplementation) {
        super(useOldPrivilegeEvaluationImplementation);
    }

    @Override
    protected String getEndpointPrefix() {
        return LEGACY_OPENDISTRO_PREFIX;
    }
}
