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

import java.util.Date;

import com.nimbusds.jwt.JWTClaimsSet;

public class JwtClaimsBuilder {
    private final JWTClaimsSet.Builder builder;

    public JwtClaimsBuilder() {
        this.builder = new JWTClaimsSet.Builder();
    }

    public JwtClaimsBuilder issueTime(Date issueTime) {
        builder.issueTime(issueTime);
        return this;
    }

    public JwtClaimsBuilder notBeforeTime(Date notBeforeTime) {
        builder.notBeforeTime(notBeforeTime);
        return this;
    }

    public JwtClaimsBuilder subject(String subject) {
        builder.subject(subject);
        return this;
    }

    public JwtClaimsBuilder issuer(String issuer) {
        builder.issuer(issuer);
        return this;
    }

    public JwtClaimsBuilder audience(String audience) {
        builder.audience(audience);
        return this;
    }

    public JwtClaimsBuilder issuedAt(Date issuedAt) {
        builder.issueTime(issuedAt);
        return this;
    }

    public JwtClaimsBuilder expirationTime(Date expirationTime) {
        builder.expirationTime(expirationTime);
        return this;
    }

    public JwtClaimsBuilder addCustomClaim(String claimName, String value) {
        builder.claim(claimName, value);
        return this;
    }

    public JWTClaimsSet build() {
        return builder.build();
    }

}
