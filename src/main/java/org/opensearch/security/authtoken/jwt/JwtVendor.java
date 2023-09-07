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

import java.util.List;
import java.util.Optional;
import java.util.function.LongSupplier;

import org.apache.cxf.jaxrs.json.basic.JsonMapObjectReaderWriter;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;
import org.apache.cxf.rs.security.jose.jws.JwsUtils;
import org.apache.cxf.rs.security.jose.jwt.JoseJwtProducer;
import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.apache.cxf.rs.security.jose.jwt.JwtUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.ssl.util.ExceptionUtils;

public class JwtVendor {
    private static final Logger logger = LogManager.getLogger(JwtVendor.class);

    private static JsonMapObjectReaderWriter jsonMapReaderWriter = new JsonMapObjectReaderWriter();

    private final String claimsEncryptionKey;
    private final JsonWebKey signingKey;
    private final JoseJwtProducer jwtProducer;
    private final LongSupplier timeProvider;
    private final EncryptionDecryptionUtil encryptionDecryptionUtil;
    private final Integer defaultExpirySeconds = 300;
    private final Integer maxExpirySeconds = 600;

    public JwtVendor(final Settings settings, final Optional<LongSupplier> timeProvider) {
        JoseJwtProducer jwtProducer = new JoseJwtProducer();
        try {
            this.signingKey = JwkUtil.createJwkFromSettings(settings);
        } catch (Exception e) {
            throw ExceptionUtils.createJwkCreationException(e);
        }
        this.jwtProducer = jwtProducer;
        if (settings.get("encryption_key") == null) {
            throw new IllegalArgumentException("encryption_key cannot be null");
        } else {
            this.claimsEncryptionKey = settings.get("encryption_key");
            this.encryptionDecryptionUtil = new EncryptionDecryptionUtil(claimsEncryptionKey);
        }
        if (timeProvider.isPresent()) {
            this.timeProvider = timeProvider.get();
        } else {
            this.timeProvider = () -> System.currentTimeMillis() / 1000;
        }
    }

    public String createJwt(
        String issuer,
        String subject,
        String audience,
        Integer expirySeconds,
        List<String> roles,
        List<String> backendRoles,
        boolean roleSecurityMode
    ) throws Exception {
        final long nowAsMillis = timeProvider.getAsLong();

        jwtProducer.setSignatureProvider(JwsUtils.getSignatureProvider(signingKey));
        JwtClaims jwtClaims = new JwtClaims();
        JwtToken jwt = new JwtToken(jwtClaims);

        jwtClaims.setIssuer(issuer);

        jwtClaims.setIssuedAt(nowAsMillis);

        jwtClaims.setSubject(subject);

        jwtClaims.setAudience(audience);

        jwtClaims.setNotBefore(nowAsMillis);

        if (expirySeconds > maxExpirySeconds) {
            throw new Exception("The provided expiration time exceeds the maximum allowed duration of " + maxExpirySeconds + " seconds");
        }

        expirySeconds = (expirySeconds == null) ? defaultExpirySeconds : Math.min(expirySeconds, maxExpirySeconds);
        if (expirySeconds <= 0) {
            throw new Exception("The expiration time should be a positive integer");
        }
        long expiryTime = timeProvider.getAsLong() + expirySeconds;
        jwtClaims.setExpiryTime(expiryTime);

        if (roles != null) {
            String listOfRoles = String.join(",", roles);
            jwtClaims.setProperty("er", encryptionDecryptionUtil.encrypt(listOfRoles));
        } else {
            throw new Exception("Roles cannot be null");
        }

        if (!roleSecurityMode && backendRoles != null) {
            String listOfBackendRoles = String.join(",", backendRoles);
            jwtClaims.setProperty("br", listOfBackendRoles);
        }

        String encodedJwt = jwtProducer.processJwt(jwt);

        if (logger.isDebugEnabled()) {
            logger.debug(
                "Created JWT: "
                    + encodedJwt
                    + "\n"
                    + jsonMapReaderWriter.toJson(jwt.getJwsHeaders())
                    + "\n"
                    + JwtUtils.claimsToJson(jwt.getClaims())
            );
        }

        return encodedJwt;
    }
}
