/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.test.framework;

import java.io.IOException;

import org.apache.commons.lang3.StringUtils;

import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

public class OnBehalfOfConfig implements ToXContentObject {
    private Boolean oboEnabled;
    private String encryption_key;
    private String algorithm;
    // HMAC
    private String signing_key;
    // EC
    private String ec_private_key;
    private String ec_private;
    private String ec_x_coordinate;
    private String ec_y_coordinate;
    // RSA
    private String rsa_private_key;
    private String rsa_modulus;
    private String rsa_public_exp;
    private String rsa_private_exp;
    private String rsa_first_prime_factor;
    private String rsa_second_prime_factor;
    private String rsa_first_prime_crt;
    private String rsa_second_prime_crt;
    private String rsa_first_crt_coefficient;

    public OnBehalfOfConfig oboEnabled(Boolean oboEnabled) {
        this.oboEnabled = oboEnabled;
        return this;
    }

    public OnBehalfOfConfig signingKey(String signing_key) {
        this.signing_key = signing_key;
        return this;
    }

    public OnBehalfOfConfig algorithm(String algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    public OnBehalfOfConfig encryptionKey(String encryption_key) {
        this.encryption_key = encryption_key;
        return this;
    }

    public OnBehalfOfConfig ecPrivateKey(String ec_private_key) {
        this.ec_private_key = ec_private_key;
        return this;
    }

    public OnBehalfOfConfig ecPrivate(String ec_private) {
        this.ec_private = ec_private;
        return this;
    }

    public OnBehalfOfConfig ecXCoordinate(String ec_x_coordinate) {
        this.ec_x_coordinate = ec_x_coordinate;
        return this;
    }

    public OnBehalfOfConfig ecYCoordinate(String ec_y_coordinate) {
        this.ec_y_coordinate = ec_y_coordinate;
        return this;
    }

    public OnBehalfOfConfig rsaPrivateKey(String rsa_private_key) {
        this.rsa_private_key = rsa_private_key;
        return this;
    }

    public OnBehalfOfConfig rsaModulus(String rsa_modulus) {
        this.rsa_modulus = rsa_modulus;
        return this;
    }

    public OnBehalfOfConfig rsaPublicExp(String rsa_public_exp) {
        this.rsa_public_exp = rsa_public_exp;
        return this;
    }

    public OnBehalfOfConfig rsaPrivateExp(String rsa_private_exp) {
        this.rsa_private_exp = rsa_private_exp;
        return this;
    }

    public OnBehalfOfConfig rsaFirstPrimeFactor(String rsa_first_prime_factor) {
        this.rsa_first_prime_factor = rsa_first_prime_factor;
        return this;
    }

    public OnBehalfOfConfig rsaSecondPrimeFactor(String rsa_second_prime_factor) {
        this.rsa_second_prime_factor = rsa_second_prime_factor;
        return this;
    }

    public OnBehalfOfConfig rsaFirstPrimeCrt(String rsa_first_prime_crt) {
        this.rsa_first_prime_crt = rsa_first_prime_crt;
        return this;
    }

    public OnBehalfOfConfig rsaSecondPrimeCrt(String rsa_second_prime_crt) {
        this.rsa_second_prime_crt = rsa_second_prime_crt;
        return this;
    }

    public OnBehalfOfConfig rsaFirstCrtCoefficient(String rsa_first_crt_coefficient) {
        this.rsa_first_crt_coefficient = rsa_first_crt_coefficient;
        return this;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder xContentBuilder, ToXContent.Params params) throws IOException {
        xContentBuilder.startObject();
        xContentBuilder.field("enabled", oboEnabled);
        xContentBuilder.field("signing_key", signing_key);
        if (StringUtils.isNoneBlank(algorithm)) {
            xContentBuilder.field("algorithm", algorithm);
        }
        if (StringUtils.isNoneBlank(encryption_key)) {
            xContentBuilder.field("encryption_key", encryption_key);
        }
        if (StringUtils.isNoneBlank(ec_private_key)) {
            xContentBuilder.field("ec_private_key", ec_private_key);
        }
        if (StringUtils.isNoneBlank(ec_private)) {
            xContentBuilder.field("ec_private", ec_private);
        }
        if (StringUtils.isNoneBlank(ec_x_coordinate)) {
            xContentBuilder.field("ec_x_coordinate", ec_x_coordinate);
        }
        if (StringUtils.isNoneBlank(ec_y_coordinate)) {
            xContentBuilder.field("ec_y_coordinate", ec_y_coordinate);
        }
        if (StringUtils.isNoneBlank(rsa_private_key)) {
            xContentBuilder.field("rsa_private_key", rsa_private_key);
        }
        if (StringUtils.isNoneBlank(rsa_modulus)) {
            xContentBuilder.field("rsa_modulus", rsa_modulus);
        }
        if (StringUtils.isNoneBlank(rsa_public_exp)) {
            xContentBuilder.field("rsa_public_exp", rsa_public_exp);
        }
        if (StringUtils.isNoneBlank(rsa_private_exp)) {
            xContentBuilder.field("rsa_private_exp", rsa_private_exp);
        }
        if (StringUtils.isNoneBlank(rsa_first_prime_factor)) {
            xContentBuilder.field("rsa_first_prime_factor", rsa_first_prime_factor);
        }
        if (StringUtils.isNoneBlank(rsa_second_prime_factor)) {
            xContentBuilder.field("rsa_second_prime_factor", rsa_second_prime_factor);
        }
        if (StringUtils.isNoneBlank(rsa_first_prime_crt)) {
            xContentBuilder.field("rsa_first_prime_crt", rsa_first_prime_crt);
        }
        if (StringUtils.isNoneBlank(rsa_second_prime_crt)) {
            xContentBuilder.field("rsa_second_prime_crt", rsa_second_prime_crt);
        }
        if (StringUtils.isNoneBlank(rsa_first_crt_coefficient)) {
            xContentBuilder.field("rsa_first_crt_coefficient", rsa_first_crt_coefficient);
        }
        xContentBuilder.endObject();
        return xContentBuilder;
    }
}
