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

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.LongSupplier;

import com.google.common.io.BaseEncoding;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.cxf.rs.security.jose.jwa.AlgorithmUtils;
import org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;
import org.apache.cxf.rs.security.jose.jwk.KeyType;
import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactConsumer;
import org.apache.cxf.rs.security.jose.jws.JwsSignatureVerifier;
import org.apache.cxf.rs.security.jose.jws.JwsUtils;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;

import static org.apache.cxf.rs.security.jose.jwk.JsonWebKey.EC_CURVE_P521;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class JwtVendorTest {

    public static final String ENCRYPTION_KEY = "encryption_key";
    public static final String ALGORITHM = "algorithm";
    public static final String EC_X = "ec_x";
    public static final String EC_Y = "ec_y";
    public static final String EC_PRIVATE = "ec_private";
    public static final String RSA_MODULUS = "rsa_modulus";
    public static final String RSA_PUBLIC_EXP = "rsa_public_exp";
    public static final String RSA_PRIVATE_EXP = "rsa_private_exp";
    private String issuer = "cluster_0";
    private String subject = "admin";
    private String audience = "audience_0";
    private List<String> roles = List.of("IT", "HR");
    private List<String> backendRoles = List.of("Sales");
    private Integer expirySeconds = 300;
    private LongSupplier currentTime = () -> (int) 100;
    private Long expectedExp = currentTime.getAsLong() + (expirySeconds);
    private String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
    private String expectedRoles = "IT,HR";

    private static PublicKey getPublicKey(String publicKey, SignatureAlgorithm algorithm) throws NoSuchAlgorithmException,
        InvalidKeySpecException {
        publicKey = publicKey.replace("-----BEGIN PUBLIC KEY-----", "").replaceAll("\n|\r\n", "").replace("-----END PUBLIC KEY-----", "");
        if (AlgorithmUtils.isEc(String.valueOf(algorithm))) {
            byte[] decoded = BaseEncoding.base64().decode(publicKey);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);

            return keyFactory.generatePublic(keySpec);
        } else {
            byte[] decoded = BaseEncoding.base64().decode(publicKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);

            return keyFactory.generatePublic(keySpec);
        }
    }

    public static boolean validateJWTSignatureUsingPublicKey(String encodedJwt, SignatureAlgorithm algorithm, String publicKey)
        throws NoSuchAlgorithmException, InvalidKeySpecException {
        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(encodedJwt);
        PublicKey ecPublicKey = getPublicKey(publicKey, algorithm);

        JwsSignatureVerifier verifier = JwsUtils.getPublicKeySignatureVerifier(ecPublicKey, algorithm);
        return jwtConsumer.verifySignatureWith(verifier);
    }

    public static boolean validateJWTSignatureUsingJWK(String encodedJwt, SignatureAlgorithm algorithm, JsonWebKey jsonWebKey) {
        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(encodedJwt);

        JwsSignatureVerifier verifier = JwsUtils.getSignatureVerifier(jsonWebKey, algorithm);
        return jwtConsumer.verifySignatureWith(verifier);
    }

    @Test
    public void testCreateHMACJwkFromSettings() {
        // try default algorithm: HS512
        Settings settings = Settings.builder().put("signing_key", "abc123").build();

        JsonWebKey jwk = JwtVendor.createJwkFromSettings(settings);
        Assert.assertEquals("HS512", jwk.getAlgorithm());
        Assert.assertEquals("sig", jwk.getPublicKeyUse().toString());
        Assert.assertEquals("abc123", jwk.getProperty("k"));

        settings = Settings.builder().put(ALGORITHM, "HS512").put("signing_key", "abc123").build();

        jwk = JwtVendor.createJwkFromSettings(settings);
        Assert.assertEquals("HS512", jwk.getAlgorithm());
        Assert.assertEquals("sig", jwk.getPublicKeyUse().toString());
        Assert.assertEquals("abc123", jwk.getProperty("k"));
    }

    @Test
    public void testCreateJwkFromSettingsWithoutSigningKey() {
        Settings settings = Settings.builder().put("jwt", "").build();
        Throwable exception = Assert.assertThrows(RuntimeException.class, () -> {
            try {
                JwtVendor.createJwkFromSettings(settings);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        Assert.assertEquals(
            "java.lang.IllegalArgumentException: Settings for signing key is missing. Please specify at least the option signing_key with a shared secret.",
            exception.getMessage()
        );
    }

    @Test
    public void testCreateJwtWithRoles() throws Exception {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        List<String> roles = List.of("IT", "HR");
        List<String> backendRoles = List.of("Sales", "Support");
        String expectedRoles = "IT,HR";
        int expirySeconds = 300;
        LongSupplier currentTime = () -> (long) 100;
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
        Settings settings = Settings.builder().put("signing_key", "abc123").put("encryption_key", claimsEncryptionKey).build();
        Long expectedExp = currentTime.getAsLong() + expirySeconds;

        JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(currentTime));
        String encodedJwt = jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles, true);

        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(encodedJwt);
        JwtToken jwt = jwtConsumer.getJwtToken();

        Assert.assertEquals("cluster_0", jwt.getClaim("iss"));
        Assert.assertEquals("admin", jwt.getClaim("sub"));
        Assert.assertEquals("audience_0", jwt.getClaim("aud"));
        Assert.assertNotNull(jwt.getClaim("iat"));
        Assert.assertNotNull(jwt.getClaim("exp"));
        Assert.assertEquals(expectedExp, jwt.getClaim("exp"));
        EncryptionDecryptionUtil encryptionUtil = new EncryptionDecryptionUtil(claimsEncryptionKey);
        Assert.assertEquals(expectedRoles, encryptionUtil.decrypt(jwt.getClaim("er").toString()));
        Assert.assertNull(jwt.getClaim("br"));
    }

    @Test
    public void testCreateJwtWithRoleSecurityMode() throws Exception {
        String issuer = "cluster_0";
        String subject = "admin";
        String audience = "audience_0";
        List<String> roles = List.of("IT", "HR");
        List<String> backendRoles = List.of("Sales", "Support");
        String expectedRoles = "IT,HR";
        String expectedBackendRoles = "Sales,Support";

        int expirySeconds = 300;
        LongSupplier currentTime = () -> (long) 100;
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);
        Settings settings = Settings.builder()
            .put("signing_key", "abc123")
            .put("encryption_key", claimsEncryptionKey)
            // CS-SUPPRESS-SINGLE: RegexpSingleline get Extensions Settings
            .put(ConfigConstants.EXTENSIONS_BWC_PLUGIN_MODE, "true")
            // CS-ENFORCE-SINGLE
            .build();
        Long expectedExp = currentTime.getAsLong() + expirySeconds;

        JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(currentTime));
        String encodedJwt = jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles, false);

        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(encodedJwt);
        JwtToken jwt = jwtConsumer.getJwtToken();

        Assert.assertEquals("cluster_0", jwt.getClaim("iss"));
        Assert.assertEquals("admin", jwt.getClaim("sub"));
        Assert.assertEquals("audience_0", jwt.getClaim("aud"));
        Assert.assertNotNull(jwt.getClaim("iat"));
        Assert.assertNotNull(jwt.getClaim("exp"));
        Assert.assertEquals(expectedExp, jwt.getClaim("exp"));
        EncryptionDecryptionUtil encryptionUtil = new EncryptionDecryptionUtil(claimsEncryptionKey);
        Assert.assertEquals(expectedRoles, encryptionUtil.decrypt(jwt.getClaim("er").toString()));
        Assert.assertNotNull(jwt.getClaim("br"));
        Assert.assertEquals(expectedBackendRoles, jwt.getClaim("br"));
    }

    @Test
    public void testCreateHMACJwkFromSettingsWithoutProperConfig() {
        Settings settings = Settings.builder().build();

        Exception e = assertThrows(Exception.class, () -> JwtVendor.createJwkFromSettings(settings));
        assertEquals(
            "Settings for signing key is missing. Please specify at least the option signing_key with a shared secret.",
            e.getMessage()
        );

        e = assertThrows(
            Exception.class,
            () -> JwtVendor.createJwkFromSettings(Settings.builder().put(settings).put(ALGORITHM, "HS512").build())
        );
        assertEquals(
            "Settings for signing key is missing. Please specify at least the option signing_key with a shared secret.",
            e.getMessage()
        );

        // correct config at this point
        JwtVendor.createJwkFromSettings(
            Settings.builder().put(settings).put(ALGORITHM, "HS512").put("signing_key", "secret_signing_key").build()
        );
    }

    @Test
    public void testPayloadCreateHMACSignedJWTWithRoles() throws Exception {
        Settings settings = Settings.builder()
            .put(ALGORITHM, "HS256")
            .put("signing_key", "abc123")
            .put(ENCRYPTION_KEY, claimsEncryptionKey)
            .build();

        JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(currentTime));
        String encodedJwt = jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles, true);

        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(encodedJwt);
        JwtToken jwt = jwtConsumer.getJwtToken();

        Assert.assertEquals("cluster_0", jwt.getClaim("iss"));
        Assert.assertEquals("admin", jwt.getClaim("sub"));
        Assert.assertEquals("audience_0", jwt.getClaim("aud"));
        Assert.assertNotNull(jwt.getClaim("iat"));
        Assert.assertNotNull(jwt.getClaim("exp"));
        Assert.assertEquals(expectedExp, jwt.getClaim("exp"));
        Assert.assertNotEquals(expectedRoles, jwt.getClaim("er"));
    }

    @Test(expected = Exception.class)
    public void testCreateJwtWithBadEncryptionKey() throws Exception {
        Settings settings = Settings.builder().put("signing_key", "abc123").build();
        JwtVendor jwtVendor = new JwtVendor(settings, Optional.empty());

        jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles, true);
    }

    @Test
    public void testCreateJwtWithBadRoles() {
        Settings settings = Settings.builder()
            .put("signing_key", "abc123")
            .put(ENCRYPTION_KEY, claimsEncryptionKey)
            .put(ALGORITHM, "HS256")
            .build();

        JwtVendor jwtVendor = new JwtVendor(settings, Optional.empty());
        Exception e = assertThrows(
            Exception.class,
            () -> jwtVendor.createJwt(issuer, subject, audience, expirySeconds, null, backendRoles, false)
        );
        Assert.assertEquals("Roles cannot be null", e.getMessage());
    }

    @Test
    public void testPayloadECSignedJWT() throws Exception {
        Settings settings = Settings.builder()
            .put(ALGORITHM, "ES512")
            .put(EC_X, RandomStringUtils.randomAlphanumeric(16))
            .put(EC_Y, RandomStringUtils.randomAlphanumeric(16))
            .put(EC_PRIVATE, RandomStringUtils.randomAlphanumeric(88))
            .put(ENCRYPTION_KEY, claimsEncryptionKey)
            .build();

        JsonWebKey jwk = JwtVendor.createJwkFromSettings(settings);
        Assert.assertEquals("sig", jwk.getPublicKeyUse().toString());
        Assert.assertEquals(EC_CURVE_P521, jwk.getProperty("crv"));
        Assert.assertEquals(KeyType.EC, jwk.getKeyType());

        JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(currentTime));
        String encodedJwt = jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles, false);

        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(encodedJwt);
        JwtToken jwt = jwtConsumer.getJwtToken();

        Assert.assertEquals("ES512", jwt.getJwsHeaders().getAlgorithm());
        Assert.assertEquals("cluster_0", jwt.getClaim("iss"));
        Assert.assertEquals("admin", jwt.getClaim("sub"));
        Assert.assertEquals("audience_0", jwt.getClaim("aud"));
        Assert.assertNotNull(jwt.getClaim("iat"));
        Assert.assertNotNull(jwt.getClaim("exp"));
        Assert.assertEquals(expectedExp, jwt.getClaim("exp"));
        Assert.assertNotEquals(expectedRoles, jwt.getClaim("er"));
    }

    @Test
    public void testEC256KeySignedJWT() throws Exception {
        String privateKey = "-----BEGIN EC PRIVATE KEY-----\n"
            + "MHcCAQEEIKtPaRgmI5T3Y3q65FywDdn3oU+1eXkmozQSi2dn3g06oAoGCCqGSM49\n"
            + "AwEHoUQDQgAETRfeqI5k3mAbuRJzu/wNuAMsiT66dr3xdKe/tmVQ85jT73Z7GbAA\n"
            + "ORUDZpXDP99AizX7U+OdEliSVZoXHHMLKw==\n"
            + "-----END EC PRIVATE KEY-----";
        String publicKey = "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETRfeqI5k3mAbuRJzu/wNuAMsiT66\n"
            + "dr3xdKe/tmVQ85jT73Z7GbAAORUDZpXDP99AizX7U+OdEliSVZoXHHMLKw==\n"
            + "-----END PUBLIC KEY-----";
        Settings settings = Settings.builder()
            .put(ALGORITHM, "ES256")
            .put("ec_private_key", privateKey)
            .put(ENCRYPTION_KEY, claimsEncryptionKey)
            .build();

        JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(currentTime));
        String encodedJwt = jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles, false);

        Assert.assertTrue(validateJWTSignatureUsingPublicKey(encodedJwt, SignatureAlgorithm.ES256, publicKey));
    }

    @Test
    public void testEC384KeySignedJWT() throws Exception {
        // create keys using openssl: "openssl ecparam -name secp384r1 -genkey -noout -out 384private-key.pem" for private key
        // "openssl ec -in 384private-key.pem -pubout -out 384public-key.pem" for public key
        String privateKey = "-----BEGIN EC PRIVATE KEY-----\n"
            + "MIGkAgEBBDB5WKs0x6dQugmyN3Cn1nzf18AKtPClzgoNeqjdsU5mvg+WSX5btLjk\n"
            + "Y2s9oRbxqxmgBwYFK4EEACKhZANiAARwnzmM7/HJuISxbvw4Z0zK3rMVej0qsB9G\n"
            + "Zeb0sL7SZfO89ONX37qNgvzxGOAonFq3uBJDqkf0AGtKlm7e8hfb+vnppIVHsota\n"
            + "f8hqKLpbYeYueQ7+H7ilCFpqYgRdiao=\n"
            + "-----END EC PRIVATE KEY-----";
        String publicKey = "-----BEGIN PUBLIC KEY-----\n"
            + "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEcJ85jO/xybiEsW78OGdMyt6zFXo9KrAf\n"
            + "RmXm9LC+0mXzvPTjV9+6jYL88RjgKJxat7gSQ6pH9ABrSpZu3vIX2/r56aSFR7KL\n"
            + "Wn/Iaii6W2HmLnkO/h+4pQhaamIEXYmq\n"
            + "-----END PUBLIC KEY-----";
        Settings settings = Settings.builder()
            .put(ALGORITHM, "ES384")
            .put("ec_private_key", privateKey)
            .put(ENCRYPTION_KEY, claimsEncryptionKey)
            .build();

        JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(currentTime));
        String encodedJwt = jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles, false);

        Assert.assertTrue(validateJWTSignatureUsingPublicKey(encodedJwt, SignatureAlgorithm.ES384, publicKey));
    }

    @Test
    public void testEC512KeySignedJWT() throws Exception {
        // create keys using openssl: "openssl ecparam -name secp521r1 -genkey -noout -out 521private-key.pem" for private key
        // "openssl ec -in 521private-key.pem -pubout -out 521public-key.pem" for public key
        String privateKey = "-----BEGIN EC PRIVATE KEY-----\n"
            + "MIHcAgEBBEIBbsJFVgSOjHSQh8Ma1PhYr0GNMihRI4WydekXZtJVSrinYYINHOj5\n"
            + "qD9v10nq7WNg85Fu9KV9xRyN2SYlYI+zByCgBwYFK4EEACOhgYkDgYYABABXzFZp\n"
            + "VE8C0G39Q8clamzs8zW9pX1cKNuTqz8XcSr6PyWl24EBqTnoea+tMPS0np0MW19r\n"
            + "/Exb+QzlKuy4XTkgwQBziwDspBgsOepT67BHCeuDcwkNJHisSs0NbAw5eu2u/eKc\n"
            + "1TjQCu6DI/HchRewpx5P4pdEm50oKXoEq3ngne8VUA==\n"
            + "-----END EC PRIVATE KEY-----\n";
        String publicKey = "-----BEGIN PUBLIC KEY-----\n"
            + "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAV8xWaVRPAtBt/UPHJWps7PM1vaV9\n"
            + "XCjbk6s/F3Eq+j8lpduBAak56HmvrTD0tJ6dDFtfa/xMW/kM5SrsuF05IMEAc4sA\n"
            + "7KQYLDnqU+uwRwnrg3MJDSR4rErNDWwMOXrtrv3inNU40ArugyPx3IUXsKceT+KX\n"
            + "RJudKCl6BKt54J3vFVA=\n"
            + "-----END PUBLIC KEY-----";
        Settings settings = Settings.builder()
            .put(ALGORITHM, "ES512")
            .put("ec_private_key", privateKey)
            .put(ENCRYPTION_KEY, claimsEncryptionKey)
            .build();

        JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(currentTime));
        String encodedJwt = jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles, false);

        Assert.assertTrue(validateJWTSignatureUsingPublicKey(encodedJwt, SignatureAlgorithm.ES512, publicKey));
    }

    @Test
    public void testCreateECJwkFromSettingsWithoutProperConfig() {
        String privateKey = "-----BEGIN EC PRIVATE KEY-----\n" + "INCORRECT KEY" + "-----END EC PRIVATE KEY-----\n";

        Settings keyBasedSettings = Settings.builder().put(ALGORITHM, "ES256").put("ec_private_key", privateKey).build();
        Exception e = assertThrows(Exception.class, () -> JwtVendor.createJwkFromSettings(keyBasedSettings));
        assertEquals("Unable to read EC private key.", e.getMessage());

        Settings settings = Settings.builder().put(ALGORITHM, "ES256").build();
        e = assertThrows(Exception.class, () -> JwtVendor.createJwkFromSettings(settings));
        assertEquals(
            "Settings for EC private key is missing. Please specify ec_private with required x and y coordinates.",
            e.getMessage()
        );

        e = assertThrows(
            Exception.class,
            () -> JwtVendor.createJwkFromSettings(
                Settings.builder().put(settings).put(EC_PRIVATE, RandomStringUtils.randomAlphanumeric(88)).build()
            )
        );
        assertEquals("Settings for EC x coordinate is missing.", e.getMessage());

        e = assertThrows(
            Exception.class,
            () -> JwtVendor.createJwkFromSettings(
                Settings.builder()
                    .put(settings)
                    .put(EC_PRIVATE, RandomStringUtils.randomAlphanumeric(88))
                    .put(EC_X, RandomStringUtils.randomAlphanumeric(10))
                    .build()
            )
        );
        assertEquals("Settings for EC y coordinate is missing.", e.getMessage());

        // correct config at this point
        JwtVendor.createJwkFromSettings(
            Settings.builder()
                .put(settings)
                .put(EC_PRIVATE, RandomStringUtils.randomAlphanumeric(88))
                .put(EC_X, RandomStringUtils.randomAlphanumeric(10))
                .put(EC_Y, RandomStringUtils.randomAlphanumeric(10))
                .build()
        );
    }

    @Test
    public void testCreateRSASignedJWTFromSettings() throws Exception {
        String kty = "jwt.key.kty";
        String alg = "jwt.key.alg";
        String rsaN = "jwt.key.n";
        String rsaE = "jwt.key.e";
        String rsaD = "jwt.key.d";
        String rsaP = "jwt.key.p";
        String rsaQ = "jwt.key.q";
        String rsaDP = "jwt.key.dp";
        String rsaDQ = "jwt.key.dq";
        String rsaQI = "jwt.key.qi";
        Settings settings = Settings.builder()
            .put(ENCRYPTION_KEY, claimsEncryptionKey)
            .put(ALGORITHM, "RS256")
            .put(
                RSA_MODULUS,
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
            )
            .put(RSA_PUBLIC_EXP, "AQAB")
            .put(
                RSA_PRIVATE_EXP,
                "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q"
            )
            .build();
        JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(() -> 100));
        String encodedJwt = jwtVendor.createJwt("issuer", "subject", "audience", 200, List.of("IT", "HR"), backendRoles, false);
        JsonWebKey jsonWebKey = new JsonWebKey(
            Map.of(
                "kty",
                "RSA",
                "n",
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e",
                "AQAB"
            )
        );
        Assert.assertTrue(validateJWTSignatureUsingJWK(encodedJwt, SignatureAlgorithm.RS256, jsonWebKey));

        // other way of creating jwk, without pre-defined properties, to check properties mapping look at JsonWebKey.class
        settings = Settings.builder()
            .put(ENCRYPTION_KEY, claimsEncryptionKey)
            .put(kty, "RSA")
            .put(alg, "RS256")
            .put(
                rsaN,
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
            )
            .put(rsaE, "AQAB")
            .put(
                rsaD,
                "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q"
            )
            .put(
                rsaP,
                "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs"
            )
            .put(
                rsaQ,
                "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk"
            )
            .put(
                rsaDP,
                "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0"
            )
            .put(
                rsaDQ,
                "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk"
            )
            .put(
                rsaQI,
                "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa - Bk0KWNGDjJHZDdDmFhW3AN7lI - puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU"
            )
            .build();
        jwtVendor = new JwtVendor(settings, Optional.of(() -> 100));
        encodedJwt = jwtVendor.createJwt("issuer", "subject", "audience", 200, List.of("IT", "HR"), backendRoles, false);
        jsonWebKey = new JsonWebKey(
            Map.of(
                "kty",
                "RSA",
                "n",
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e",
                "AQAB",
                "p",
                "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
                "q",
                "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
                "dp",
                "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
                "dq",
                "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
                "qi",
                "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa - Bk0KWNGDjJHZDdDmFhW3AN7lI - puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU"
            )
        );
        Assert.assertTrue(validateJWTSignatureUsingJWK(encodedJwt, SignatureAlgorithm.RS256, jsonWebKey));

        // only n, e, p is required
        settings = Settings.builder()
            .put(ENCRYPTION_KEY, claimsEncryptionKey)
            .put(kty, "RSA")
            .put(alg, "RS256")
            .put(
                rsaN,
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
            )
            .put(rsaE, "AQAB")
            .put(
                rsaD,
                "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q"
            )
            .build();

        jwtVendor = new JwtVendor(settings, Optional.of(() -> 100));
        encodedJwt = jwtVendor.createJwt("issuer", "subject", "audience", 200, List.of("IT", "HR"), backendRoles, false);
        jsonWebKey = new JsonWebKey(
            Map.of(
                "kty",
                "RSA",
                "n",
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e",
                "AQAB"
            )
        );
        Assert.assertTrue(validateJWTSignatureUsingJWK(encodedJwt, SignatureAlgorithm.RS256, jsonWebKey));
    }

    @Test
    public void testRSA256KeySignedJWT() throws Exception {
        String privateKey = "-----BEGIN PRIVATE KEY-----\n"
            + "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDAB1QyTM+i2djr\n"
            + "mPnbPJ5/NjfielSeR4s1U5hC7wcUMzt2Y65/tvWuOD7b8BlM68bvTWpHaSiAhQVt\n"
            + "10pLxZAfTbDtRy53MT6CAZKL//EdNDTuIr+YRWMyN9nLhwLD445nSwwJmlrurm61\n"
            + "/LU57jtvYe393JemkuRzT0KbMASb2L9mebjF4qvBos2qu3JyGD+6oFOPPB7l02Tw\n"
            + "aqHoZQWcz+CYWLtuUYP3Qz6UlNzoRckr4PbuK+x7Svk/KUBnuPMZCmbj5FJKi/s6\n"
            + "+r9L9LeljslYJpwfzL+CXLLzKkoaQKZddz7DCE33NK9DMaZdmHxOJqySAL6JBZHB\n"
            + "oTU5Wy7jAgMBAAECggEAGC/0ItUk+YIPaMw0ezESqmWrEAZQ6TzhY8lQmOxgS7g7\n"
            + "nv5lnjrujXq9LtklFANwuSIFpygE4idJ10YyWq1FqYO7gNpMl9Z75UaLGGztCGd+\n"
            + "hpju4XWqox/WJDowbCRvV+25KZkn0f+Q/LBE0slXSCt2yC6ZwBv+1X1gH4miqE8i\n"
            + "RF4bjuhY4OERRYqwFy3wqWdmnJEQVqtc3tG7RN5z4ppk01oUCXdikvMkWJzg9OMC\n"
            + "heIbqjmduBpHpXQf5TpO9xmliEQJnxvQ5GToKHatM+qPlth+So0cwByeYQJgpp9Y\n"
            + "fRR4TteRcWdlAezcZ5cdKxJNiW0Rq5vZZI3lIMCS6QKBgQD+UiBXt5jjpUrHqrk3\n"
            + "qLJbDoOQCxEx814lNrLHP9nk6FJq+ltdxVhluZYF3WAc3HRDdPT3hsx1s4jQYxDt\n"
            + "CJafpG8s+TfInThXO/nvYPERH43o1/TMCJX+uMdtf5r2smADpsNzMINNW/0YMSfL\n"
            + "aBJfPMMELJRdn1dlJGFIcZarmwKBgQDBS+lIa97JPvh3F71KbRWTpcoDNgb0VhVa\n"
            + "XpyYzmBmkYffE53WIBPgC8l0PvHBs8aqa7P6WUzZHO2Zkj8pp4/QQvEuvqUZL7Qj\n"
            + "15++GbP2/eyhizon8lk+pf2KH7HyJYRMd1CXQr1Pwq9kirH+LMQpKtChjlsonspm\n"
            + "gwEn59PyWQKBgQDeDslsrcNSKbYkpt24SpUIyqB3OiKWcb/nUF5DeW4A4BVukREL\n"
            + "zE9F6wiiMExGhvsBF3L5WfrWXp98DLPvs4sI82ObajOZ+CUEjjrKF+QFJn8bKsz1\n"
            + "Bh4p3h9LbZraAp+xMIAB6P8MoeBYqjrr8P/xpjVFRMN7B7Egf+ZtgbikNwKBgGB8\n"
            + "DNkKhy07EnkXz3O8GZ4WjkymBjimU4hFW7NmqHXqRMEUIKAGaQVXvNoapUBEBXGB\n"
            + "y1e2hYaGSw9yEbcwHbgeAheMMArvZeLSObmBSPSL8Tb9sSzJasS7xF/SzFcLZQtq\n"
            + "Lz8hoC+VBUmRdaFjJRNLfNJ3pYcUJAGheM07ie8ZAoGBAMLguVp5Kn74GQ0ExtxB\n"
            + "zHO9AKejR8d3SckQFFcVtH+OYJ+X05ZxRRTvG7PzCziiTSoVf7wNHi0ebxq7YFvd\n"
            + "2QesN8EgxwXiUOrPeUELpXhfZ7ztri1E/MACw9ETbdyEL5bh4vKDpaJr4FTwVojJ\n"
            + "E5KVj7rUSwDJJi6NRWTIk12S\n"
            + "-----END PRIVATE KEY-----";
        String publicKey = "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwAdUMkzPotnY65j52zye\n"
            + "fzY34npUnkeLNVOYQu8HFDM7dmOuf7b1rjg+2/AZTOvG701qR2kogIUFbddKS8WQ\n"
            + "H02w7UcudzE+ggGSi//xHTQ07iK/mEVjMjfZy4cCw+OOZ0sMCZpa7q5utfy1Oe47\n"
            + "b2Ht/dyXppLkc09CmzAEm9i/Znm4xeKrwaLNqrtychg/uqBTjzwe5dNk8Gqh6GUF\n"
            + "nM/gmFi7blGD90M+lJTc6EXJK+D27ivse0r5PylAZ7jzGQpm4+RSSov7Ovq/S/S3\n"
            + "pY7JWCacH8y/glyy8ypKGkCmXXc+wwhN9zSvQzGmXZh8TiaskgC+iQWRwaE1OVsu\n"
            + "4wIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";

        Settings settings = Settings.builder()
            .put(ENCRYPTION_KEY, RandomStringUtils.randomAlphanumeric(16))
            .put(ALGORITHM, "RS256")
            .put("rsa_private_key", privateKey)
            .build();

        JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(() -> 100));
        String encodedJwt = jwtVendor.createJwt("issuer", "subject", "audience", 200, List.of("IT", "HR"), backendRoles, false);
        Assert.assertTrue(validateJWTSignatureUsingPublicKey(encodedJwt, SignatureAlgorithm.RS256, publicKey));
    }

    @Test
    public void testRSA384KeySignedJWT() throws Exception {
        String privateKey = "-----BEGIN PRIVATE KEY-----\n"
            + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCrHDjPwb+DKEKh\n"
            + "ZD/5fity+yOtEvX5yNuR9QMNUiDjBOdeM5Q+JBcCydeGUYpDibAr3R1BaOpzK9XZ\n"
            + "oRI4jehP0RiwS9n0yRvvOdomX5sYz1Azzxle8FQ00hmPSks5JGGfmN7H/q8yLR+X\n"
            + "5assB545tmJgDGi8kDABUzMZPrn8zR2zkUKvIqGXXn4Xet34WM8AXrgpHYFR6qht\n"
            + "EKAIUYRn4O08EF/NdXxyAWHCepOIvbI+C73KmRIFQSmexrxfINs8zpZnEJqlXYiP\n"
            + "A/UJafS18eEc4ivh2pcIEOLgGA3ix3PdaNhj3Cjo2lNFN9SVoHRKzOullJfA9Q3v\n"
            + "PIW+3bqfAgMBAAECggEAA4RufzLL4C3ShM/Ikt/Zk8updZQnXe2XjzNapIpKJnCC\n"
            + "MwkGD0BIVXnXBin57h56nRmL/D1kXbQKeXvv9x1Pp7MJegztG4o2Gp+f+4bz62Qj\n"
            + "kWpnP/DabPA0BKKHKP21oLAQmvWCHhrDBKkncMhtTmFl5J83WJzxfQLRUOpdrLPK\n"
            + "vaA7YePnWPRC/zgPSHQgGJlIPdxHy6LGCQdMTqDvdMckLJ7z1R7aWxOsygi5/Z17\n"
            + "Ihx2k/7cXaLjnZEn77TO8jdyupTKm3Ixb62DpYbYxWrOJL9foXYgtRSTG7AUKJcr\n"
            + "HO2LjsXpKBm5e1yJcvM3UJ5wu7nUUtnTu4vHkMZgGQKBgQDeMzbrn9syUmUBlFw+\n"
            + "wl8njtH0pQ4R8Ox5LzNVQulbYJj901NrrPYjo/eWe7nj1zE5uqRmSrKW1CQCW4TU\n"
            + "xm1QPn5eojEYOmaI4Hx04K6XtuVnnqnnb43aU4uJzoDS/F9Qzx9N9a2j9sk1iasO\n"
            + "A88L78/8/zj8Mj7ABszeFOmyCQKBgQDFI39cxNw2ouQmLfnh+L14DV1ZrLDFci1n\n"
            + "4EaBCcVigNE9ZczcjK70GmRmVOAJSlZD8/IO6qUC108FCMWoN2xxfkEW21seavB/\n"
            + "LweU3Uq2/OmHi4zaaQjFFxeSFzly1Mx3B7OEGVcKV+m7oUJSDY75WMktdE4bMM82\n"
            + "v6Qc/wCRZwKBgB8r/CZuFKgomvbvw0kip4q7JIU3qpOlwub1UjRB4M7q7Eufm/Jd\n"
            + "H2K8m/1GejuWctdwcaPQEuHJ/Qs/n5DiDW/WdI/+HPkTKFNHeu5Cnvu1stUokxle\n"
            + "sv3P/qFkkPoIYa7Kf8/GCYgZFP0nxRGAQ0mfaQRLIclvmxIBYjg9otNRAoGAEsd9\n"
            + "43VxUNcVirmIe0k5q00Cnn8/258zyhhoPvSSU/7Xb9TZvgy8wc4d0E23hcsKCrEb\n"
            + "VuZtT6b5BQ6/3XViJDGVu7qrpGsle8gcHccyzdmr2Vim00t8JWI8wZLqyxCQZapb\n"
            + "JHNRgk+7mT8UVUKrYv9dMrJImnh81MdOt+BmynMCgYEAnqCnZHD9LnKIhOLnSKAI\n"
            + "VsDhaFHrDWbedG9WsIbI7pb7majW+wxUWFCx9pMOVDzS8ykoixPS3NggkCtxF10i\n"
            + "YPhHfx0DhvPQsv4VzR6jhWGpnL4OS3H+piZbTDKip5swIsM5IV2YLBE569y1eTmJ\n"
            + "xzoZ1r2eLYjHOEhZx28887Q=\n"
            + "-----END PRIVATE KEY-----";
        String publicKey = "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqxw4z8G/gyhCoWQ/+X4r\n"
            + "cvsjrRL1+cjbkfUDDVIg4wTnXjOUPiQXAsnXhlGKQ4mwK90dQWjqcyvV2aESOI3o\n"
            + "T9EYsEvZ9Mkb7znaJl+bGM9QM88ZXvBUNNIZj0pLOSRhn5jex/6vMi0fl+WrLAee\n"
            + "ObZiYAxovJAwAVMzGT65/M0ds5FCryKhl15+F3rd+FjPAF64KR2BUeqobRCgCFGE\n"
            + "Z+DtPBBfzXV8cgFhwnqTiL2yPgu9ypkSBUEpnsa8XyDbPM6WZxCapV2IjwP1CWn0\n"
            + "tfHhHOIr4dqXCBDi4BgN4sdz3WjYY9wo6NpTRTfUlaB0SszrpZSXwPUN7zyFvt26\n"
            + "nwIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";

        Settings settings = Settings.builder()
            .put(ENCRYPTION_KEY, RandomStringUtils.randomAlphanumeric(16))
            .put(ALGORITHM, "RS384")
            .put("rsa_private_key", privateKey)
            .build();

        JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(() -> 100));
        String encodedJwt = jwtVendor.createJwt("issuer", "subject", "audience", 200, List.of("IT", "HR"), backendRoles, false);
        Assert.assertTrue(validateJWTSignatureUsingPublicKey(encodedJwt, SignatureAlgorithm.RS384, publicKey));
    }

    @Test
    public void testRSA512KeySignedJWT() throws Exception {
        String privateKey = "-----BEGIN PRIVATE KEY-----\n"
            + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCrHDjPwb+DKEKh\n"
            + "ZD/5fity+yOtEvX5yNuR9QMNUiDjBOdeM5Q+JBcCydeGUYpDibAr3R1BaOpzK9XZ\n"
            + "oRI4jehP0RiwS9n0yRvvOdomX5sYz1Azzxle8FQ00hmPSks5JGGfmN7H/q8yLR+X\n"
            + "5assB545tmJgDGi8kDABUzMZPrn8zR2zkUKvIqGXXn4Xet34WM8AXrgpHYFR6qht\n"
            + "EKAIUYRn4O08EF/NdXxyAWHCepOIvbI+C73KmRIFQSmexrxfINs8zpZnEJqlXYiP\n"
            + "A/UJafS18eEc4ivh2pcIEOLgGA3ix3PdaNhj3Cjo2lNFN9SVoHRKzOullJfA9Q3v\n"
            + "PIW+3bqfAgMBAAECggEAA4RufzLL4C3ShM/Ikt/Zk8updZQnXe2XjzNapIpKJnCC\n"
            + "MwkGD0BIVXnXBin57h56nRmL/D1kXbQKeXvv9x1Pp7MJegztG4o2Gp+f+4bz62Qj\n"
            + "kWpnP/DabPA0BKKHKP21oLAQmvWCHhrDBKkncMhtTmFl5J83WJzxfQLRUOpdrLPK\n"
            + "vaA7YePnWPRC/zgPSHQgGJlIPdxHy6LGCQdMTqDvdMckLJ7z1R7aWxOsygi5/Z17\n"
            + "Ihx2k/7cXaLjnZEn77TO8jdyupTKm3Ixb62DpYbYxWrOJL9foXYgtRSTG7AUKJcr\n"
            + "HO2LjsXpKBm5e1yJcvM3UJ5wu7nUUtnTu4vHkMZgGQKBgQDeMzbrn9syUmUBlFw+\n"
            + "wl8njtH0pQ4R8Ox5LzNVQulbYJj901NrrPYjo/eWe7nj1zE5uqRmSrKW1CQCW4TU\n"
            + "xm1QPn5eojEYOmaI4Hx04K6XtuVnnqnnb43aU4uJzoDS/F9Qzx9N9a2j9sk1iasO\n"
            + "A88L78/8/zj8Mj7ABszeFOmyCQKBgQDFI39cxNw2ouQmLfnh+L14DV1ZrLDFci1n\n"
            + "4EaBCcVigNE9ZczcjK70GmRmVOAJSlZD8/IO6qUC108FCMWoN2xxfkEW21seavB/\n"
            + "LweU3Uq2/OmHi4zaaQjFFxeSFzly1Mx3B7OEGVcKV+m7oUJSDY75WMktdE4bMM82\n"
            + "v6Qc/wCRZwKBgB8r/CZuFKgomvbvw0kip4q7JIU3qpOlwub1UjRB4M7q7Eufm/Jd\n"
            + "H2K8m/1GejuWctdwcaPQEuHJ/Qs/n5DiDW/WdI/+HPkTKFNHeu5Cnvu1stUokxle\n"
            + "sv3P/qFkkPoIYa7Kf8/GCYgZFP0nxRGAQ0mfaQRLIclvmxIBYjg9otNRAoGAEsd9\n"
            + "43VxUNcVirmIe0k5q00Cnn8/258zyhhoPvSSU/7Xb9TZvgy8wc4d0E23hcsKCrEb\n"
            + "VuZtT6b5BQ6/3XViJDGVu7qrpGsle8gcHccyzdmr2Vim00t8JWI8wZLqyxCQZapb\n"
            + "JHNRgk+7mT8UVUKrYv9dMrJImnh81MdOt+BmynMCgYEAnqCnZHD9LnKIhOLnSKAI\n"
            + "VsDhaFHrDWbedG9WsIbI7pb7majW+wxUWFCx9pMOVDzS8ykoixPS3NggkCtxF10i\n"
            + "YPhHfx0DhvPQsv4VzR6jhWGpnL4OS3H+piZbTDKip5swIsM5IV2YLBE569y1eTmJ\n"
            + "xzoZ1r2eLYjHOEhZx28887Q=\n"
            + "-----END PRIVATE KEY-----";
        String publicKey = "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqxw4z8G/gyhCoWQ/+X4r\n"
            + "cvsjrRL1+cjbkfUDDVIg4wTnXjOUPiQXAsnXhlGKQ4mwK90dQWjqcyvV2aESOI3o\n"
            + "T9EYsEvZ9Mkb7znaJl+bGM9QM88ZXvBUNNIZj0pLOSRhn5jex/6vMi0fl+WrLAee\n"
            + "ObZiYAxovJAwAVMzGT65/M0ds5FCryKhl15+F3rd+FjPAF64KR2BUeqobRCgCFGE\n"
            + "Z+DtPBBfzXV8cgFhwnqTiL2yPgu9ypkSBUEpnsa8XyDbPM6WZxCapV2IjwP1CWn0\n"
            + "tfHhHOIr4dqXCBDi4BgN4sdz3WjYY9wo6NpTRTfUlaB0SszrpZSXwPUN7zyFvt26\n"
            + "nwIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";

        Settings settings = Settings.builder()
            .put(ENCRYPTION_KEY, RandomStringUtils.randomAlphanumeric(16))
            .put(ALGORITHM, "RS512")
            .put("rsa_private_key", privateKey)
            .build();

        JwtVendor jwtVendor = new JwtVendor(settings, Optional.of(() -> 100));
        String encodedJwt = jwtVendor.createJwt("issuer", "subject", "audience", 200, List.of("IT", "HR"), backendRoles, false);
        Assert.assertTrue(validateJWTSignatureUsingPublicKey(encodedJwt, SignatureAlgorithm.RS512, publicKey));
    }

    @Test
    public void testCreateRSAJwkFromSettingsWithoutProperConfig() {
        String privateKey = "-----BEGIN PRIVATE KEY-----\n" + "incorrectKey" + "-----END PRIVATE KEY-----";
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);

        Settings settings1 = Settings.builder()
            .put(ENCRYPTION_KEY, claimsEncryptionKey)
            .put(ALGORITHM, "RS256")
            .put("rsa_private_key", privateKey)
            .build();
        Exception e = assertThrows(Exception.class, () -> JwtVendor.createJwkFromSettings(settings1));
        assertEquals("Unable to read RSA private key.", e.getMessage());

        Settings settings2 = Settings.builder()
            .put(ENCRYPTION_KEY, claimsEncryptionKey)
            .put(ALGORITHM, "RS256")
            .put(RSA_PUBLIC_EXP, "AQAB")
            .put(
                RSA_PRIVATE_EXP,
                "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q"
            )
            .build();
        e = assertThrows(Exception.class, () -> JwtVendor.createJwkFromSettings(settings2));
        assertEquals("Settings for RSA modulus is missing. Please specify rsa_modulus.", e.getMessage());

        final Exception finalE = assertThrows(
            Exception.class,
            () -> JwtVendor.createJwkFromSettings(
                Settings.builder()
                    .put(settings2)
                    .put(RSA_MODULUS, "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R")
                    .put("rsa_first_prime_factor", "some_prime")
                    .build()
            )
        );
        List<String> expectedList = List.of(
            "Settings for RSA key is missing, missing properties:",
            "rsa_second_prime_factor",
            "rsa_first_prime_crt",
            "rsa_second_prime_crt",
            "rsa_first_crt_coefficient"
        );
        expectedList.forEach(v -> Assert.assertTrue(finalE.getMessage().contains(v)));

    }

    @Test
    public void testIncorrectAlgorithmName() {
        Settings settings = Settings.builder()
            .put("signing_key", "abc123")
            .put(ENCRYPTION_KEY, claimsEncryptionKey)
            .put(ALGORITHM, "NON EXISTING SIGNING ALGO")
            .build();

        Exception e = assertThrows(Exception.class, () -> new JwtVendor(settings, Optional.empty()));
        Assert.assertEquals(
            "An error occurred during the creation of Jwk: Signing algorithm not recognized: NON EXISTING SIGNING ALGO",
            e.getMessage()
        );
    }

    @Test
    public void testCreateJwtWithBadExpiry() {
        Integer expirySeconds = -300;
        String claimsEncryptionKey = RandomStringUtils.randomAlphanumeric(16);

        Settings settings = Settings.builder().put("signing_key", "abc123").put("encryption_key", claimsEncryptionKey).build();
        JwtVendor jwtVendor = new JwtVendor(settings, Optional.empty());

        Exception e = assertThrows(
            Exception.class,
            () -> jwtVendor.createJwt(issuer, subject, audience, expirySeconds, roles, backendRoles, false)
        );
        Assert.assertEquals("The expiration time should be a positive integer", e.getMessage());
    }

}
