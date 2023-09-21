/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework.certificate;

import java.security.Provider;
import java.util.Optional;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import static org.opensearch.test.framework.certificate.AlgorithmKit.ecdsaSha256withEcdsa;
import static org.opensearch.test.framework.certificate.AlgorithmKit.rsaSha256withRsa;

/**
* The class defines static factory method for class {@link CertificatesIssuer}. Object of class {@link CertificatesIssuer} created by
* various factory methods differs in terms of cryptographic algorithms used for certificates creation.
*
*/
class CertificatesIssuerFactory {

    private static final int KEY_SIZE = 2048;

    private CertificatesIssuerFactory() {

    }

    private static final Provider DEFAULT_SECURITY_PROVIDER = new BouncyCastleProvider();

    /**
    * @see {@link #rsaBaseCertificateIssuer(Provider)}
    */
    public static CertificatesIssuer rsaBaseCertificateIssuer() {
        return rsaBaseCertificateIssuer(null);
    }

    /**
    * The method creates {@link CertificatesIssuer} which uses RSA algorithm for certificate creation.
    * @param securityProvider determines cryptographic algorithm implementation, can be <code>null</code>.
    * @return new instance of {@link CertificatesIssuer}
    */
    public static CertificatesIssuer rsaBaseCertificateIssuer(Provider securityProvider) {
        Provider provider = Optional.ofNullable(securityProvider).orElse(DEFAULT_SECURITY_PROVIDER);
        return new CertificatesIssuer(provider, rsaSha256withRsa(provider, KEY_SIZE));
    }

    /**
    * {@link #rsaBaseCertificateIssuer(Provider)}
    */
    public static CertificatesIssuer ecdsaBaseCertificatesIssuer() {
        return ecdsaBaseCertificatesIssuer(null);
    }

    /**
    * It creates {@link CertificatesIssuer} which uses asymmetric cryptography algorithm which relays on elliptic curves.
    * @param securityProvider determines cryptographic algorithm implementation, can be <code>null</code>.
    * @return new instance of {@link CertificatesIssuer}
    */
    public static CertificatesIssuer ecdsaBaseCertificatesIssuer(Provider securityProvider) {
        Provider provider = Optional.ofNullable(securityProvider).orElse(DEFAULT_SECURITY_PROVIDER);
        return new CertificatesIssuer(provider, ecdsaSha256withEcdsa(securityProvider, "P-384"));
    }
}
