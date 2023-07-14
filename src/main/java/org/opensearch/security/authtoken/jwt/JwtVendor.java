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

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.function.LongSupplier;

import com.google.common.base.Strings;
import org.apache.cxf.jaxrs.json.basic.JsonMapObjectReaderWriter;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;
import org.apache.cxf.rs.security.jose.jwk.KeyType;
import org.apache.cxf.rs.security.jose.jwk.PublicKeyUse;
import org.apache.cxf.rs.security.jose.jws.JwsUtils;
import org.apache.cxf.rs.security.jose.jwt.JoseJwtProducer;
import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.apache.cxf.rs.security.jose.jwt.JwtUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;

public class JwtVendor {
    private static final Logger logger = LogManager.getLogger(JwtVendor.class);

    private static JsonMapObjectReaderWriter jsonMapReaderWriter = new JsonMapObjectReaderWriter();

    private final String claimsEncryptionKey;
    private final JsonWebKey signingKey;
    private final JoseJwtProducer jwtProducer;
    private final LongSupplier timeProvider;

    public JwtVendor(final Settings settings, final Optional<LongSupplier> timeProvider) {
        JoseJwtProducer jwtProducer = new JoseJwtProducer();
        try {
            this.signingKey = createJwkFromSettings(settings);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        this.jwtProducer = jwtProducer;
        if (settings.get("encryption_key") == null) {
            throw new RuntimeException("encryption_key cannot be null");
        } else {
            this.claimsEncryptionKey = settings.get("encryption_key");
        }
        if (timeProvider.isPresent()) {
            this.timeProvider = timeProvider.get();
        } else {
            this.timeProvider = () -> System.currentTimeMillis() / 1000;
        }
    }

    /*
     * The default configuration of this web key should be:
     *   KeyType: OCTET
     *   PublicKeyUse: SIGN
     *   Encryption Algorithm: HS512
     * */
    static JsonWebKey createJwkFromSettings(Settings settings) throws Exception {
        String signingKey = settings.get("signing_key");

        if (!Strings.isNullOrEmpty(signingKey)) {

            JsonWebKey jwk = new JsonWebKey();

            jwk.setKeyType(KeyType.OCTET);
            jwk.setAlgorithm("HS512");
            jwk.setPublicKeyUse(PublicKeyUse.SIGN);
            jwk.setProperty("k", signingKey);

            return jwk;
        } else {
            Settings jwkSettings = settings.getAsSettings("jwt").getAsSettings("key");

            if (jwkSettings.isEmpty()) {
                throw new Exception("Settings for key is missing. Please specify at least the option signing_key with a shared secret.");
            }

            JsonWebKey jwk = new JsonWebKey();

            for (String key : jwkSettings.keySet()) {
                jwk.setProperty(key, jwkSettings.get(key));
            }

            return jwk;
        }
    }

    public String createJwt(
        String issuer,
        String subject,
        String audience,
        Integer expirySeconds,
        List<String> roles,
        List<String> backendRoles
    ) throws Exception {
        String tokenIdentifier = "obo";
        long timeMillis = timeProvider.getAsLong();
        Instant now = Instant.ofEpochMilli(timeProvider.getAsLong());

        jwtProducer.setSignatureProvider(JwsUtils.getSignatureProvider(signingKey));
        JwtClaims jwtClaims = new JwtClaims();
        JwtToken jwt = new JwtToken(jwtClaims);

        jwtClaims.setProperty("typ", tokenIdentifier);

        jwtClaims.setIssuer(issuer);

        jwtClaims.setIssuedAt(timeMillis);

        jwtClaims.setSubject(subject);

        jwtClaims.setAudience(audience);

        jwtClaims.setNotBefore(timeMillis);

        if (expirySeconds == null) {
            long expiryTime = timeProvider.getAsLong() + 300;
            jwtClaims.setExpiryTime(expiryTime);
        } else if (expirySeconds > 0) {
            long expiryTime = timeProvider.getAsLong() + expirySeconds;
            jwtClaims.setExpiryTime(expiryTime);
        } else {
            throw new Exception("The expiration time should be a positive integer");
        }

        if (roles != null) {
            String listOfRoles = String.join(",", roles);
            jwtClaims.setProperty("er", EncryptionDecryptionUtil.encrypt(claimsEncryptionKey, listOfRoles));
        } else {
            throw new Exception("Roles cannot be null");
        }

        /* TODO: If the backendRoles is not null and the BWC Mode is on, put them into the "dbr" claim */

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
