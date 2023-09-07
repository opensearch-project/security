/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.authtoken.jwt;

import io.jsonwebtoken.io.Decoders;
import org.apache.cxf.rs.security.jose.jwa.AlgorithmUtils;
import org.apache.cxf.rs.security.jose.jwk.JsonWebKey;
import org.apache.cxf.rs.security.jose.jwk.JwkUtils;
import org.apache.cxf.rs.security.jose.jwk.KeyType;
import org.apache.cxf.rs.security.jose.jwk.PublicKeyUse;
import org.opensearch.common.settings.Settings;

import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import static org.apache.cxf.rs.security.jose.jwa.AlgorithmUtils.ES_SHA_256_ALGO;
import static org.apache.cxf.rs.security.jose.jwa.AlgorithmUtils.ES_SHA_384_ALGO;
import static org.apache.cxf.rs.security.jose.jwa.AlgorithmUtils.ES_SHA_512_ALGO;
import static org.apache.cxf.rs.security.jose.jwk.JsonWebKey.EC_CURVE;
import static org.apache.cxf.rs.security.jose.jwk.JsonWebKey.EC_CURVE_P256;
import static org.apache.cxf.rs.security.jose.jwk.JsonWebKey.EC_CURVE_P384;
import static org.apache.cxf.rs.security.jose.jwk.JsonWebKey.EC_CURVE_P521;
import static org.apache.cxf.rs.security.jose.jwk.JsonWebKey.EC_PRIVATE_KEY;
import static org.apache.cxf.rs.security.jose.jwk.JsonWebKey.EC_X_COORDINATE;
import static org.apache.cxf.rs.security.jose.jwk.JsonWebKey.EC_Y_COORDINATE;
import static org.apache.cxf.rs.security.jose.jwk.JsonWebKey.RSA_FIRST_CRT_COEFFICIENT;
import static org.apache.cxf.rs.security.jose.jwk.JsonWebKey.RSA_FIRST_PRIME_CRT;
import static org.apache.cxf.rs.security.jose.jwk.JsonWebKey.RSA_FIRST_PRIME_FACTOR;
import static org.apache.cxf.rs.security.jose.jwk.JsonWebKey.RSA_MODULUS;
import static org.apache.cxf.rs.security.jose.jwk.JsonWebKey.RSA_PRIVATE_EXP;
import static org.apache.cxf.rs.security.jose.jwk.JsonWebKey.RSA_PUBLIC_EXP;
import static org.apache.cxf.rs.security.jose.jwk.JsonWebKey.RSA_SECOND_PRIME_CRT;
import static org.apache.cxf.rs.security.jose.jwk.JsonWebKey.RSA_SECOND_PRIME_FACTOR;

public class JwkUtil {
    /*
     * The default configuration of this web key should be:
     *   KeyType: OCTET
     *   PublicKeyUse: SIGN
     *   Encryption Algorithm: HS512
     * */
    static JsonWebKey createJwkFromSettings(Settings settings) {
        String algorithm = settings.get("algorithm");
        Settings jwkSettings = settings.getAsSettings("jwt").getAsSettings("key");

        if (algorithm != null) {
            return getSigningJwk(algorithm.toUpperCase(Locale.ROOT), settings);
        } else if (!jwkSettings.isEmpty()) {
            JsonWebKey jwk = new JsonWebKey();

            for (String key : jwkSettings.keySet()) {
                jwk.setProperty(key, jwkSettings.get(key));
            }

            return jwk;
        } else {
            // try default
            return getSigningJwk("HS512", settings);
        }
    }

    private static JsonWebKey getSigningJwk(String algorithm, Settings settings) throws IllegalArgumentException {
        JsonWebKey jwk;

        if (AlgorithmUtils.isOctet(algorithm)) {
            jwk = new JsonWebKey();
            jwk.setPublicKeyUse(PublicKeyUse.SIGN);
            jwk.setKeyType(KeyType.OCTET);
            String signingKey = Optional.ofNullable(settings.get("signing_key"))
                .orElseThrow(
                    () -> new IllegalArgumentException(
                        "Settings for signing key is missing. Please specify at least the option signing_key with a shared secret."
                    )
                );
            jwk.setProperty("k", signingKey);
            jwk.setAlgorithm(algorithm);
        } else if (AlgorithmUtils.isEcDsaSign(algorithm)) {
            jwk = getECSigningJWK(algorithm, settings);
        } else if (AlgorithmUtils.isRsaSign(algorithm)) {
            jwk = getRsaSigningJWK(algorithm, settings);
        } else {
            throw new IllegalArgumentException("Signing algorithm not recognized: " + algorithm);
        }
        return jwk;
    }

    private static JsonWebKey getRsaSigningJWK(String algorithm, Settings settings) {
        JsonWebKey jwk;
        // try load private key
        if (settings.get("rsa_private_key") != null) {
            try {
                String privateKey = settings.get("rsa_private_key")
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll("\n|\r\n", "")
                    .replace("-----END PRIVATE KEY-----", "");

                byte[] decoded = Decoders.BASE64.decode(privateKey);

                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
                RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
                jwk = JwkUtils.fromRSAPrivateKey(rsaPrivateKey, algorithm);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new RuntimeException("Unable to read RSA private key.", e);
            }
        } else {
            jwk = new JsonWebKey();
            jwk.setPublicKeyUse(PublicKeyUse.SIGN);
            jwk.setKeyType(KeyType.RSA);
            jwk.setAlgorithm(algorithm);

            jwk.setProperty(
                RSA_MODULUS,
                Optional.ofNullable(settings.get("rsa_modulus"))
                    .orElseThrow(() -> new IllegalArgumentException("Settings for RSA modulus is missing. Please specify rsa_modulus."))
            );
            jwk.setProperty(
                RSA_PUBLIC_EXP,
                Optional.ofNullable(settings.get("rsa_public_exp"))
                    .orElseThrow(
                        () -> new IllegalArgumentException("Settings for RSA public exponent is missing. Please specify rsa_public_exp.")
                    )
            );
            jwk.setProperty(
                RSA_PRIVATE_EXP,
                Optional.ofNullable(settings.get("rsa_private_exp"))
                    .orElseThrow(
                        () -> new IllegalArgumentException("Settings for RSA private exponent is missing. Please specify rsa_private_exp.")
                    )
            );

            // optional settings, we need either none, or all of those
            List<String> rsaMissingSettings = new ArrayList<>();
            Map<String, String> optionalRSAParameters = Map.of(
                "rsa_first_prime_factor",
                RSA_FIRST_PRIME_FACTOR,
                "rsa_second_prime_factor",
                RSA_SECOND_PRIME_FACTOR,
                "rsa_first_prime_crt",
                RSA_FIRST_PRIME_CRT,
                "rsa_second_prime_crt",
                RSA_SECOND_PRIME_CRT,
                "rsa_first_crt_coefficient",
                RSA_FIRST_CRT_COEFFICIENT
            );
            optionalRSAParameters.forEach(
                (param, variable) -> Optional.ofNullable(settings.get(param))
                    .ifPresentOrElse(v -> jwk.setProperty(variable, v), () -> rsaMissingSettings.add(param))
            );

            if (!rsaMissingSettings.isEmpty() && rsaMissingSettings.size() != 5) {
                // incorrect optional settings
                throw new IllegalArgumentException(
                    "Settings for RSA key is missing, missing properties: " + String.join(", ", rsaMissingSettings)
                );
            }
        }
        return jwk;
    }

    private static JsonWebKey getECSigningJWK(String algorithm, Settings settings) {
        JsonWebKey jwk = new JsonWebKey();
        jwk.setPublicKeyUse(PublicKeyUse.SIGN);
        jwk.setKeyType(KeyType.EC);
        jwk.setAlgorithm(algorithm);
        jwk.setProperty(EC_CURVE, calcCurve(algorithm));
        // try to load key from file
        if (settings.get("ec_private_key") != null) {
            try {
                StringReader rdr = new StringReader(settings.get("ec_private_key"));
                Object parsed = new org.bouncycastle.openssl.PEMParser(rdr).readObject();
                ECPrivateKey privateKey = (ECPrivateKey) new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter().getKeyPair(
                    (org.bouncycastle.openssl.PEMKeyPair) parsed
                ).getPrivate();
                jwk.setProperty(EC_PRIVATE_KEY, Base64.getUrlEncoder().encodeToString(privateKey.getS().toByteArray()));
            } catch (IOException e) {
                throw new IllegalArgumentException("Unable to read EC private key.", e);
            }
        } else {
            jwk.setProperty(
                EC_PRIVATE_KEY,
                Optional.ofNullable(settings.get("ec_private"))
                    .orElseThrow(
                        () -> new IllegalArgumentException(
                            "Settings for EC private key is missing. Please specify ec_private with required x and y coordinates."
                        )
                    )
            );
            jwk.setProperty(
                EC_X_COORDINATE,
                Optional.ofNullable(settings.get("ec_x"))
                    .orElseThrow(() -> new IllegalArgumentException("Settings for EC x coordinate is missing."))
            );
            jwk.setProperty(
                EC_Y_COORDINATE,
                Optional.ofNullable(settings.get("ec_y"))
                    .orElseThrow(() -> new IllegalArgumentException("Settings for EC y coordinate is missing."))
            );
        }
        return jwk;
    }

    private static String calcCurve(String algorithm) {
        switch (algorithm) {
            case ES_SHA_256_ALGO:
                return EC_CURVE_P256;
            case ES_SHA_384_ALGO:
                return EC_CURVE_P384;
            case ES_SHA_512_ALGO:
                return EC_CURVE_P521;
            default:
                throw new IllegalArgumentException("Not recognized Elliptic Curve algorithm: " + algorithm);
        }
    }
}
