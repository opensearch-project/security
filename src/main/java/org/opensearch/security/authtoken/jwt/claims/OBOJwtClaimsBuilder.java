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

package org.opensearch.security.authtoken.jwt.claims;

import java.util.List;

public class OBOJwtClaimsBuilder extends JwtClaimsBuilder {

    public OBOJwtClaimsBuilder(String encryptionKey) {
        super();
        this.encryptionKey(encryptionKey);
    }

    public OBOJwtClaimsBuilder addRoles(List<String> roles) {
        final String listOfRoles = String.join(",", roles);
        this.addCustomClaimWithEncryption("er", listOfRoles);
        return this;
    }

    public OBOJwtClaimsBuilder addBackendRoles(Boolean includeBackendRoles, List<String> backendRoles) {
        if (includeBackendRoles && backendRoles != null) {
            final String listOfBackendRoles = String.join(",", backendRoles);
            this.addCustomClaim("br", listOfBackendRoles);
        }
        return this;
    }
}
