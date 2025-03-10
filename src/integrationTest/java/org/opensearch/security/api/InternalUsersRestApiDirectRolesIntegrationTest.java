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

package org.opensearch.security.api;

import static org.opensearch.security.dlic.rest.api.InternalUsersApiAction.DIRECT_SECURITY_ROLES;

public class InternalUsersRestApiDirectRolesIntegrationTest extends AbstractInternalUsersRestApiIntegrationTest {
    @Override
    protected String getRoleField() {
        return DIRECT_SECURITY_ROLES;
    }
}
