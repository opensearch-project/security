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

import com.google.common.base.Strings;
import org.apache.cxf.jaxrs.json.basic.JsonMapObjectReaderWriter;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;
import org.apache.cxf.rs.security.jose.jwk.KeyType;
import org.apache.cxf.rs.security.jose.jwk.PublicKeyUse;
import org.apache.cxf.rs.security.jose.jws.JwsUtils;
import org.apache.cxf.rs.security.jose.jwt.JoseJwtProducer;
import org.apache.cxf.rs.security.jose.jwt.JwtClaims;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.apache.cxf.rs.security.jose.jwt.JwtUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.transport.TransportAddress;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.security.securityconf.ConfigModel;
import org.opensearch.threadpool.ThreadPool;


public class JwtVendor {
    private static final Logger logger = LogManager.getLogger(JwtVendor.class);

    private static JsonMapObjectReaderWriter jsonMapReaderWriter = new JsonMapObjectReaderWriter();

    private JsonWebKey signingKey;
    private JoseJwtProducer jwtProducer;
    private ConfigModel configModel;
    private ThreadContext threadContext;

    public JwtVendor(Settings settings) {
        JoseJwtProducer jwtProducer = new JoseJwtProducer();
        try {
            this.signingKey = createJwkFromSettings(settings);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        this.jwtProducer = jwtProducer;
    }

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
                throw new Exception(
                        "Settings for key is missing. Please specify at least the option signing_key with a shared secret.");
            }

            JsonWebKey jwk = new JsonWebKey();

            for (String key : jwkSettings.keySet()) {
                jwk.setProperty(key, jwkSettings.get(key));
            }

            return jwk;
        }
    }

    //TODO:Getting roles from User
    public Map<String, String> prepareClaimsForUser(User user, ThreadPool threadPool) {
        Map<String, String> claims = new HashMap<>();
        this.threadContext = threadPool.getThreadContext();
        final TransportAddress caller = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
        Set<String> mappedRoles = mapRoles(user, caller);
        claims.put("sub", user.getName());
        claims.put("roles", String.join(",", mappedRoles));
        return claims;
    }
    public Set<String> mapRoles(final User user, final TransportAddress caller) {
        return this.configModel.mapSecurityRoles(user, caller);
    }

    public String createJwt(Map<String, String> claims) {

        jwtProducer.setSignatureProvider(JwsUtils.getSignatureProvider(signingKey));
        JwtClaims jwtClaims = new JwtClaims();
        JwtToken jwt = new JwtToken(jwtClaims);

        jwtClaims.setNotBefore(System.currentTimeMillis() / 1000);
        long expiryTime = System.currentTimeMillis() / 1000 + (60 * 5);

        if (claims.containsKey("sub")) {
            jwtClaims.setSubject(claims.get("sub"));
        } else {
            throw new OpenSearchSecurityException("Cannot create jwt, 'sub' claim is required");
        }

        jwtClaims.setIssuedAt(Instant.now().toEpochMilli());

        // TODO: Should call preparelaims();
        if (claims.containsKey("roles")) {
            jwtClaims.setProperty("roles", claims.get("roles"));
        }

        if (claims.containsKey("exp")) {
            int customTime = Integer.parseInt(claims.get("exp"));
            jwtClaims.setExpiryTime(System.currentTimeMillis() / 1000 + (60 * customTime));
        } else {
            jwtClaims.setExpiryTime(expiryTime);
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
