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

// CS-SUPPRESS-SINGLE: RegexpSingleline Extension is used to refer to certificate extensions, keeping this rule disable for the whole file
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.util.Calendar;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;

import com.google.common.base.Strings;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import static java.util.Objects.requireNonNull;

/**
* <p>
* The class is used to generate public key certificate. The class hides low level details related to certificate creation and
* usage of underlying Bouncy Castle library.
* </p>
* <p>
* The public key certificate according to its name contains a public key and some metadata. The metadata describes an entity (human,
* company, web server, IoT device, etc.) which is an owner of private key associated with the certificate (private key is not included
* into certificate and is a kind of secret). The responsibility of the class is to issue a certificate. To issue a certificate it is
* necessary to provide metadata which is embedded in the certificates. The metadata is represented by the class
* {@link CertificateMetadata}. Furthermore, the class needs a public key which also must be embedded in the certificate. To obtain public
* and private key pair the class uses {@link AlgorithmKit}. The result of creating certificate is data structure {@link CertificateData}.
* The class {@link CertificateData} contains entire information which is necessary to use the certificate by its owner, that is:
* certificate and private key.
* </p>
*
* <p>
*     The class is able to create self-signed certificates or certificates signed by some entity. To create a self signed certificate
*     the method {@link #issueSignedCertificate(CertificateMetadata, CertificateData)} is used, whereas to create signed certificates
*     the method {@link #issueSignedCertificate(CertificateMetadata, CertificateData)} is employed.
* </p>
* <p>
*     The instance of the class can be obtained by invocation of static method defined in class {@link CertificatesIssuerFactory}.
* </p>
*/
class CertificatesIssuer {

    private static final Logger log = LogManager.getLogger(CertificatesIssuer.class);

    private static final AtomicLong ID_COUNTER = new AtomicLong(System.currentTimeMillis());

    private final Provider securityProvider;
    private final AlgorithmKit algorithmKit;
    private final JcaX509ExtensionUtils extUtils;

    CertificatesIssuer(Provider securityProvider, AlgorithmKit algorithmKit) {
        this.securityProvider = securityProvider;
        this.algorithmKit = algorithmKit;
        this.extUtils = getExtUtils();
    }

    /**
    * The method creates a certificate with provided metadata and public key obtained from {@link #algorithmKit}. The result of invocation
    * contains required data to use a certificate by its owner.
    *
    * @param certificateMetadata metadata which should be embedded into created certificate
    * @return {@link CertificateData} which contain certificate and private key associated with the certificate.
    */
    public CertificateData issueSelfSignedCertificate(CertificateMetadata certificateMetadata) {
        try {
            KeyPair publicAndPrivateKey = algorithmKit.generateKeyPair();
            X500Name issuerName = stringToX500Name(requireNonNull(certificateMetadata.getSubject(), "Certificate metadata are required."));
            X509CertificateHolder x509CertificateHolder = buildCertificateHolder(
                certificateMetadata,
                issuerName,
                publicAndPrivateKey.getPublic(),
                publicAndPrivateKey
            );
            return new CertificateData(x509CertificateHolder, publicAndPrivateKey);
        } catch (OperatorCreationException | CertIOException e) {
            log.error("Error while generating certificate", e);
            throw new RuntimeException("Error while generating self signed certificate", e);
        }
    }

    /**
    * The method is similar to {@link #issueSignedCertificate(CertificateMetadata, CertificateData)} but additionally it signs created
    * certificate using data from <code>parentCertificateData</code>.
    *
    * @param metadata metadata which should be embedded into created certificate
    * @param parentCertificateData data required to signe a newly issued certificate (private key among others things).
    * @return {@link CertificateData} which contain certificate and private key associated with the certificate.
    */
    public CertificateData issueSignedCertificate(CertificateMetadata metadata, CertificateData parentCertificateData) {
        try {
            KeyPair publicAndPrivateKey = algorithmKit.generateKeyPair();
            KeyPair parentKeyPair = requireNonNull(parentCertificateData, "Issuer certificate data are required").getKeyPair();
            X500Name issuerName = parentCertificateData.getCertificateSubject();
            var x509CertificateHolder = buildCertificateHolder(
                requireNonNull(metadata, "Certificate metadata are required"),
                issuerName,
                publicAndPrivateKey.getPublic(),
                parentKeyPair
            );
            return new CertificateData(x509CertificateHolder, publicAndPrivateKey);
        } catch (OperatorCreationException | CertIOException e) {
            log.error("Error while generating signed certificate", e);
            throw new RuntimeException("Error while generating signed certificate", e);
        }
    }

    private X509CertificateHolder buildCertificateHolder(
        CertificateMetadata certificateMetadata,
        X500Name issuerName,
        PublicKey certificatePublicKey,
        KeyPair parentKeyPair
    ) throws CertIOException, OperatorCreationException {
        X509v3CertificateBuilder builder = builderWithBasicExtensions(
            certificateMetadata,
            issuerName,
            certificatePublicKey,
            parentKeyPair.getPublic()
        );
        addSubjectAlternativeNameExtension(builder, certificateMetadata);
        addExtendedKeyUsageExtension(builder, certificateMetadata);
        return builder.build(createContentSigner(parentKeyPair.getPrivate()));
    }

    private ContentSigner createContentSigner(PrivateKey privateKey) throws OperatorCreationException {
        return new JcaContentSignerBuilder(algorithmKit.getSignatureAlgorithmName()).setProvider(securityProvider).build(privateKey);
    }

    private void addExtendedKeyUsageExtension(X509v3CertificateBuilder builder, CertificateMetadata certificateMetadata)
        throws CertIOException {
        if (certificateMetadata.hasExtendedKeyUsage()) {
            builder.addExtension(Extension.extendedKeyUsage, true, certificateMetadata.getExtendedKeyUsage());
        }
    }

    private X509v3CertificateBuilder builderWithBasicExtensions(
        CertificateMetadata certificateMetadata,
        X500Name issuerName,
        PublicKey certificatePublicKey,
        PublicKey parentPublicKey
    ) throws CertIOException {
        X500Name subjectName = stringToX500Name(certificateMetadata.getSubject());
        Date validityStartDate = new Date(System.currentTimeMillis() - (24 * 3600 * 1000));
        Date validityEndDate = getEndDate(validityStartDate, certificateMetadata.getValidityDays());

        BigInteger certificateSerialNumber = generateNextCertificateSerialNumber();
        return new X509v3CertificateBuilder(
            issuerName,
            certificateSerialNumber,
            validityStartDate,
            validityEndDate,
            subjectName,
            SubjectPublicKeyInfo.getInstance(certificatePublicKey.getEncoded())
        ).addExtension(Extension.basicConstraints, true, new BasicConstraints(certificateMetadata.isBasicConstrainIsCa()))
            .addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(parentPublicKey))
            .addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(certificatePublicKey))
            .addExtension(Extension.keyUsage, true, certificateMetadata.asKeyUsage());
    }

    private void addSubjectAlternativeNameExtension(X509v3CertificateBuilder builder, CertificateMetadata metadata) throws CertIOException {
        if (metadata.hasSubjectAlternativeNameExtension()) {
            DERSequence subjectAlternativeNames = metadata.createSubjectAlternativeNames();
            builder.addExtension(Extension.subjectAlternativeName, false, subjectAlternativeNames);
        }
    }

    private Date getEndDate(Date startDate, int validityDays) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.DATE, validityDays);
        return calendar.getTime();
    }

    private static JcaX509ExtensionUtils getExtUtils() {
        try {
            return new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException e) {
            log.error("Getting certificate extension utils failed", e);
            throw new RuntimeException("Getting certificate extension utils failed", e);
        }
    }

    private X500Name stringToX500Name(String distinguishedName) {
        if (Strings.isNullOrEmpty(distinguishedName)) {
            throw new RuntimeException("No DN (distinguished name) must not be null or empty");
        }
        try {
            return new X500Name(RFC4519Style.INSTANCE, distinguishedName);
        } catch (IllegalArgumentException e) {
            String message = String.format("Invalid DN (distinguished name) specified for %s certificate.", distinguishedName);
            throw new RuntimeException(message, e);
        }
    }

    private BigInteger generateNextCertificateSerialNumber() {
        return BigInteger.valueOf(ID_COUNTER.incrementAndGet());
    }
}
// CS-ENFORCE-SINGLE
