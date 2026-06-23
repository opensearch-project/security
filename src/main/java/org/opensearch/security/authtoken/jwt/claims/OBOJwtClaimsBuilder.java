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

import org.opensearch.security.authtoken.jwt.EncryptionDecryptionUtil;

public class OBOJwtClaimsBuilder extends JwtClaimsBuilder {
    private final EncryptionDecryptionUtil encryptionDecryptionUtil;

    public OBOJwtClaimsBuilder(String encryptionKey) {
        super();
        this.encryptionDecryptionUtil = encryptionKey != null ? new EncryptionDecryptionUtil(encryptionKey) : null;
    }

    public OBOJwtClaimsBuilder addRoles(List<String> roles) {
        final String listOfRoles = String.join(",", roles);
        if (encryptionDecryptionUtil != null) {
            this.addCustomClaim("encrypted_roles", encryptionDecryptionUtil.encrypt(listOfRoles));
        } else {
            this.addCustomClaim("roles", listOfRoles);
        }
        return this;
    }

    public OBOJwtClaimsBuilder addBackendRoles(Boolean includeBackendRoles, List<String> backendRoles) {
        if (includeBackendRoles && backendRoles != null) {
            final String listOfBackendRoles = String.join(",", backendRoles);
            this.addCustomClaim("backend_roles", listOfBackendRoles);
        }
        return this;
    }
}
