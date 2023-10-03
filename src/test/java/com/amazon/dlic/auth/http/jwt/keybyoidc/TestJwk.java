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

package com.amazon.dlic.auth.http.jwt.keybyoidc;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;

class TestJwk {

    // Keys generated with https://mkjwk.org/

    static final String OCT_1_K =
        "eTDZjSqRD9Abhod9iqeGX_7o93a-eElTeXWAF6FmzQshmRIrPD-C9ET3pFjJ_IBrzmWIZDk8ig-X_PIyGmKsxNMsrU-0BNWF5gJq5xOp4rYTl8z66Tw9wr8tHLxLxgJqkLSuUCRBZvlZlQ7jNdhBBxgM-hdSSzsN1T33qdIwhrUeJ-KXI5yKUXHjoWFYb9tETbYQ4NvONowkCsXK_flp-E3F_OcKe_z5iVUszAV8QfCod1zhbya540kDejXCL6N_XMmhWJqum7UJ3hgf6DEtroPSnVpHt4iR5w9ArKK-IBgluPght03gNcoNqwz7p77TFbdOmUKF_PWy1bcdbaUoSg";
    static final String OCT_2_K =
        "YP6Q3IF2qJEagV948dsicXKpG43Ci2W7ZxUpiVTBLZr1vFN9ZGUKxeXGgVWuMFYTmoHvv5AOC8BvoNOpcE3rcJNuNOqTMdujxD92CxjOykiLEKQ0Te_7xQ4LnSQjlqdIJ4U3S7qCnJLd1LxhKOGZcUhE_pjhwf7q2RUUpvC3UOyZZLog9yeflnp9nqqDy5yVqRYWZRcPI06kJTh3Z8IFi2JRJV14iUFQtOHQKuyJRMcsldKnfWl7YW3JdQ9IRN-c1lEYSEBmsavEejcqHZkbli2svqLfmCBJVWffXDRxhq0_VafiL83HC0bP9qeNKivhemw6foVmg8UMs7yJ6ao02A";
    static final String OCT_3_K =
        "r3aeW3OK7-B4Hs3hq9BmlT1D3jRiolH9PL82XUz9xAS7dniAdmvMnN5GkOc1vqibOe2T-CC_103UglDm9D0iU9S9zn6wTuQt1L5wfZIoHd9f5IjJ_YFEzZMvsoUY_-ji_0K_ugVvBPwi9JnBQHHS4zrgmP06dGjmcnZDcIf4W_iFas3lDYSXilL1V2QhNaynpSqTarpfBGSphKv4Zg2JhsX8xB0VSaTlEq4lF8pzvpWSxXCW9CtomhB80daSuTizrmSTEPpdN3XzQ2-Tovo1ieMOfDU4csvjEk7Bwc2ThjpnA8ucKQUYpUv9joBxKuCdUltssthWnetrogjYOn_xGA";

    static final JWK OCT_1 = createOct("kid/a", "HS256", OCT_1_K);
    static final JWK OCT_2 = createOct("kid/b", "HS256", OCT_2_K);
    static final JWK OCT_3 = createOct("kid/c", "HS256", OCT_3_K);
    static final JWK ESCAPED_SLASH_KID_OCT_1 = createOct("kid\\/_a", "HS256", OCT_1_K);
    static final JWK FORWARD_SLASH_KID_OCT_1 = createOct("kid/_a", "HS256", OCT_1_K);

    static final JWKSet OCT_1_2_3 = createJwks(OCT_1, OCT_2, OCT_3, FORWARD_SLASH_KID_OCT_1, ESCAPED_SLASH_KID_OCT_1);

    static final String RSA_1_D =
        "On8XGMmdM5Fm5hvuhQk-qAkIP2CoK5QMx0OH5m_WDzKXZv8lZ2eg89I4ehBiOKGdw1h_mjmWwTah-evpXV-BF5QpejPQqxkXS-8s5r2AvietQq32jl-gwIwZWTvfzjpT9On0YJZ4q01tMDj3r-YOLUW2xrz3za9tl6pPU_5kP63C-hoj1ybTwcC7ujbCPwhY6yAopMA1v10uVmCxsjsNikEjB6YePgHixez51wO3Z8mXNwefWukFWYJ5T7t4kHMSf5P_8FJZ14u5yvYZnngE_tJCyHFdIDb6UWsrgxomtlQU-SdZYK_NY6gw6mCkjjlqOoYqlsrRJ16kJ81Ds269oQ";
    static final String RSA_1_N =
        "hMSoV74FRtoaU7xpp0llsXbHE4oUseKoSNga-C_YIXuoGc3pajHh1WtJppZQNYM1Xy07nHchLJAdgqL2_q_Lk8cFHmmL1KTjwPflK9zZ9C0-8QTOrrqU9vkp3gT00jWWJ0HJbUvXIGxPGPnxoJoI--ToE0EWsYEWqWyx1TqYol--oUUPlY5r7vXRKIn5UZNz6VGkW8nI4fXaqDUpXH9uVM9A-nJX2B0Xjwu3VOn2zrgkCZeGTHjNgfLISOTFe9m8lHWLKcuxOWPuCZyCN0C6ZdWB1YP2NhxYFQwQfGV8yfnTImgL-DuV4WPSRVj7W_GJr213-oXBrBR0CnQEPbi_3w";
    static final String RSA_1_E = "AQAB";

    static final String RSA_2_D =
        "QQ18k_buZHOSVYzkXL1FaqdodZVNZ_hrBtDcmCVUYjm3dfDVQYt70h8LUdLUCSUA2-_VEwqVdQ-L2FTg7NZVvZJXIyQXp3yrdY1vGKebs3oaIB_VQT8jt-64s12r_8V2ksK2myRrvfm2Fgqi32H5QkspuaQYb9s4NJwKSk7mVAz5dRWQdCx9JNVWknWDJxgHzh3Uku1tNwUOyvSYcRnSZ9X7oWNHaHkSGLEYE_mxD7YXs6HEdCDwc3WuvR5AiVKg2OGec0lL1hY_AWX5UxnR00mhAa0qPytFfaPe-Sc5tQ5regQRqRNDyDESVGIvqXsY8ePjZPOFyoxrcJ2wN3bt4Q";
    static final String RSA_2_N =
        "lt4EID7tbrE9E8l7VfVGhiwSx4O8nLO5AZo5pJNE1fUy4bM56wH_DeU3YspXh0UvH-vcn4uKjhwJdOCjzalBc2wXD0aRd3JXzWwbjveo6oBFz6kU7VnY8nFMYLMlb6FDcl066OZOtW4PIFtAStXj5rX_J94He3sfTClodpNljTi4qeQwoNsrnZ5Eq82pCp20zCgvbdes8HQBq_QgApvzhL3c-PXd2I_4pBnaPoZwAnufthk7-v8V0Zf5CrDuqEczKKr38pvwggnxZqsfUy2X0bXPBvDXh5B2ljWxWl8tHJbKXzOhfV5Nx5rllJnNabFoVxh3hnlxdOZ88zcaslWBLQ";
    static final String RSA_2_E = "AQAB";

    static final String RSA_X_D =
        "iXym57VmwbWvcHtf--xSDPTagEJdnceuErjH6lbuabFXeBx42ZpuAICvo6_YpMcqLybD37ArIu2SD5J_ZBALp4v4KecMPFI5lZr7GKlGgqnForvcC7EWA_ZtZ9uY746cKun8NtemcOlAenn2dvc9NP2S4JtE3FHxmqs2MMmz-ki-ar8-zu0j0HLPLl_Wj2SZ9yCeFmmH3eocX5IRRiWwPnudQJM2t0kt9V-M88YzobqzoMEoFjTfi-owa-w6xGAgJxAUKk02vTiTivH3Qmkk-uAXyj-VtcyzYXD74ICN8EplcAEUKegDR59T4-u18GdpDbPU20XzxDaO4lZiQ7TIEQ";
    static final String RSA_X_N =
        "jDDVUMXOXDVcaRVAT5TtuiAsLxk7XAAwyyECfmySZul7D5XVLMtGe6rP2900q3nM4BaCEiuwXjmTCZDAGlFGs2a3eQ1vbBSv9_0KGHL-gZGFPNiv0v8aR7QzZ-abhGnRy5F52PlTWsypGgG_kQpF2t2TBotvYhvVPagAt4ljllDKvY1siOvS3nh4TqcUtWcbgQZEWPmaXuhx0eLmhQJca7UEw99YlGNew48AEzt7ZnfU0Qkz3JwSz7IcPx-NfIh6BN6LwAg_ASdoM3MR8rDOtLYavmJVhutrfOpE-4-fw1mf3eLYu7xrxIplSiOIsHunTUssnTiBkXAaGqGJs604Pw";
    static final String RSA_X_E = "AQAB";

    static final JWK RSA_1 = createRsa("kid/1", "RS256", RSA_1_E, RSA_1_N, RSA_1_D);

    static final JWK RSA_1_PUBLIC = createRsaPublic("kid/1", "RS256", RSA_1_E, RSA_1_N);
    static final JWK RSA_1_PUBLIC_NO_ALG = createRsaPublic("kid/1", null, RSA_1_E, RSA_1_N);
    static final JWK RSA_1_PUBLIC_WRONG_ALG = createRsaPublic("kid/1", "HS256", RSA_1_E, RSA_1_N);

    static final JWK RSA_2 = createRsa("kid/2", "RS256", RSA_2_E, RSA_2_N, RSA_2_D);
    static final JWK RSA_2_PUBLIC = createRsaPublic("kid/2", "RS256", RSA_2_E, RSA_2_N);

    static final JWK RSA_X = createRsa("kid/2", "RS256", RSA_X_E, RSA_X_N, RSA_X_D);
    static final JWK RSA_X_PUBLIC = createRsaPublic("kid/2", "RS256", RSA_X_E, RSA_X_N);

    static final JWKSet RSA_1_2_PUBLIC = createJwks(RSA_1_PUBLIC, RSA_2_PUBLIC);

    static class Jwks {
        static final JWKSet ALL = createJwks(OCT_1, OCT_2, OCT_3, FORWARD_SLASH_KID_OCT_1, RSA_1_PUBLIC, RSA_2_PUBLIC);
        static final JWKSet RSA_1 = createJwks(RSA_1_PUBLIC);
        static final JWKSet RSA_2 = createJwks(RSA_2_PUBLIC);
        static final JWKSet RSA_1_NO_ALG = createJwks(RSA_1_PUBLIC_NO_ALG);
        static final JWKSet RSA_1_WRONG_ALG = createJwks(RSA_1_PUBLIC_WRONG_ALG);
    }

    private static JWK createOct(String keyId, String algorithm, String k) {
        return new OctetSequenceKey.Builder(k.getBytes(StandardCharsets.UTF_8)).keyID(keyId)
            .keyUse(KeyUse.SIGNATURE)
            .algorithm(JWSAlgorithm.parse(algorithm))
            .build();
    }

    private static JWK createRsa(String keyId, String algorithm, String e, String n, String d) {
        RSAKey.Builder builder = new RSAKey.Builder(Base64URL.from(n), Base64URL.from(e)).keyUse(KeyUse.SIGNATURE)
            .algorithm(algorithm == null ? null : JWSAlgorithm.parse(algorithm))
            .keyID(keyId);

        if (d != null) {
            builder.privateExponent(Base64URL.from(d));
        }

        return builder.build();
    }

    private static JWK createRsaPublic(String keyId, String algorithm, String e, String n) {
        return createRsa(keyId, algorithm, e, n, null);
    }

    private static JWKSet createJwks(JWK... array) {
        return new JWKSet(Arrays.asList(array));
    }

}
