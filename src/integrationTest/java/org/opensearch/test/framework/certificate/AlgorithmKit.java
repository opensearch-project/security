/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
/*
* Copyright 2021 floragunn GmbH
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
*/

package org.opensearch.test.framework.certificate;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.ECGenParameterSpec;
import java.util.function.Supplier;

import com.google.common.base.Strings;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import static java.util.Objects.requireNonNull;

/**
* The class determines cryptographic algorithms used for certificate creation. To create certificate it is necessary to generate public
* and private key, so-called key pair. The class encapsulates the process of key pairs creation ({@link #generateKeyPair()}),
* thus determines algorithm used for key pair creation. Additionally, class defines also algorithms used to digitally sign a certificate.
* Please see {@link #getSignatureAlgorithmName()}
*/
class AlgorithmKit {

    private static final Logger log = LogManager.getLogger(AlgorithmKit.class);
    public static final String SIGNATURE_ALGORITHM_SHA_256_WITH_RSA = "SHA256withRSA";
    public static final String SIGNATURE_ALGORITHM_SHA_256_WITH_ECDSA = "SHA256withECDSA";

    private final String signatureAlgorithmName;
    private final Supplier<KeyPair> keyPairSupplier;

    private AlgorithmKit(String signatureAlgorithmName, Supplier<KeyPair> keyPairSupplier) {
        notEmptyAlgorithmName(signatureAlgorithmName);
        this.signatureAlgorithmName = signatureAlgorithmName;
        this.keyPairSupplier = requireNonNull(keyPairSupplier, "Key pair supplier is required.");
    }

    private static void notEmptyAlgorithmName(String signatureAlgorithmName) {
        if (Strings.isNullOrEmpty(signatureAlgorithmName)) {
            throw new RuntimeException("Algorithm name is required.");
        }
    }

    /**
    * Static factory method. ECDSA algorithm used for key pair creation. Signature algorithm is defined by field
    * {@link #SIGNATURE_ALGORITHM_SHA_256_WITH_ECDSA}
    *
    * @param securityProvider determines cryptographic algorithm implementation
    * @param ellipticCurve
    * @return new instance of class {@link AlgorithmKit}
    */
    public static AlgorithmKit ecdsaSha256withEcdsa(Provider securityProvider, String ellipticCurve) {
        notEmptyAlgorithmName(ellipticCurve);
        Supplier<KeyPair> supplier = ecdsaKeyPairSupplier(requireNonNull(securityProvider, "Security provider is required"), ellipticCurve);
        return new AlgorithmKit(SIGNATURE_ALGORITHM_SHA_256_WITH_ECDSA, supplier);
    }

    /**
    * Static factory method. It creates object of {@link AlgorithmKit} which enforces usage of RSA algorithm for key pair generation.
    * Signature algorithm is defined by {@link #SIGNATURE_ALGORITHM_SHA_256_WITH_RSA}
    *
    * @param securityProvider determines cryptographic algorithm implementation
    * @param keySize defines key size for RSA algorithm
    * @return new instance of class {@link AlgorithmKit}
    */
    public static AlgorithmKit rsaSha256withRsa(Provider securityProvider, int keySize) {
        positiveKeySize(keySize);
        Supplier<KeyPair> supplier = rsaKeyPairSupplier(securityProvider, keySize);
        return new AlgorithmKit(SIGNATURE_ALGORITHM_SHA_256_WITH_RSA, supplier);
    }

    private static void positiveKeySize(int keySize) {
        if (keySize <= 0) {
            throw new RuntimeException("Key size must be a positive integer value, provided: " + keySize);
        }
    }

    /**
    * It determines algorithm used for digital signature
    * @return algorithm name
    */
    public String getSignatureAlgorithmName() {
        return signatureAlgorithmName;
    }

    /**
    * It creates new private and public key pair
    * @return new pair of keys
    */
    public KeyPair generateKeyPair() {
        return keyPairSupplier.get();
    }

    private static Supplier<KeyPair> rsaKeyPairSupplier(Provider securityProvider, int keySize) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", securityProvider);
            log.info("Initialize key pair generator with keySize: {}", keySize);
            generator.initialize(keySize);
            return generator::generateKeyPair;
        } catch (NoSuchAlgorithmException e) {
            String message = "Error while initializing RSA asymmetric key generator.";
            log.error(message, e);
            throw new RuntimeException(message, e);
        }
    }

    private static Supplier<KeyPair> ecdsaKeyPairSupplier(Provider securityProvider, String ellipticCurve) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", securityProvider);
            log.info("Initialize key pair generator with elliptic curve: {}", ellipticCurve);
            ECGenParameterSpec ecsp = new ECGenParameterSpec(ellipticCurve);
            generator.initialize(ecsp);
            return generator::generateKeyPair;
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            String message = "Error while initializing ECDSA asymmetric key generator.";
            log.error(message, e);
            throw new RuntimeException(message, e);
        }
    }

}
