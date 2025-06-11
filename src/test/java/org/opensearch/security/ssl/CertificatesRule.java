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

package org.opensearch.security.ssl;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.rules.ExternalResource;
import org.junit.rules.TemporaryFolder;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import org.opensearch.common.collect.Tuple;

public class CertificatesRule extends ExternalResource {

    private final static BouncyCastleProvider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();

    private final TemporaryFolder temporaryFolder = new TemporaryFolder();

    final static String DEFAULT_SUBJECT_NAME = "CN=some_access,OU=client,O=client,L=test,C=de";

    private Path configRootFolder;

    private final String privateKeyPassword = RandomStringUtils.randomAlphabetic(10);

    private X509CertificateHolder caCertificateHolder;

    private X509CertificateHolder accessCertificateHolder;

    private PrivateKey accessCertificatePrivateKey;

    private final boolean generateDefaultCertificates;

    public CertificatesRule() {
        this(true);
    }

    public CertificatesRule(final boolean generateDefaultCertificates) {
        this.generateDefaultCertificates = generateDefaultCertificates;
    }

    @Override
    protected void before() throws Throwable {
        super.before();
        temporaryFolder.create();
        configRootFolder = temporaryFolder.newFolder("esHome").toPath();
        if (generateDefaultCertificates) {
            final var keyPair = generateKeyPair();
            caCertificateHolder = generateCaCertificate(keyPair);
            final var keyAndCertificate = generateAccessCertificate(keyPair);
            accessCertificatePrivateKey = keyAndCertificate.v1();
            accessCertificateHolder = keyAndCertificate.v2();
        }
    }

    @Override
    protected void after() {
        super.after();
        temporaryFolder.delete();
    }

    public Path configRootFolder() {
        return configRootFolder;
    }

    public String privateKeyPassword() {
        return privateKeyPassword;
    }

    public X509CertificateHolder caCertificateHolder() {
        return caCertificateHolder;
    }

    public X509CertificateHolder accessCertificateHolder() {
        return accessCertificateHolder;
    }

    public X509Certificate x509CaCertificate() throws CertificateException {
        return toX509Certificate(caCertificateHolder);
    }

    public X509Certificate x509AccessCertificate() throws CertificateException {
        return toX509Certificate(accessCertificateHolder);
    }

    public PrivateKey accessCertificatePrivateKey() {
        return accessCertificatePrivateKey;
    }

    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", BOUNCY_CASTLE_PROVIDER);
        generator.initialize(4096);
        return generator.generateKeyPair();
    }

    public X509CertificateHolder generateCaCertificate(final KeyPair parentKeyPair) throws IOException, NoSuchAlgorithmException,
        OperatorCreationException {
        final var startAndEndDate = generateStartAndEndDate();
        return generateCaCertificate(parentKeyPair, generateSerialNumber(), startAndEndDate.v1(), startAndEndDate.v2());
    }

    public X509CertificateHolder generateCaCertificate(final KeyPair parentKeyPair, final Instant startDate, final Instant endDate)
        throws IOException, NoSuchAlgorithmException, OperatorCreationException {
        return generateCaCertificate(parentKeyPair, generateSerialNumber(), startDate, endDate);
    }

    public X509CertificateHolder generateCaCertificate(
        final KeyPair parentKeyPair,
        final String subjectName,
        final Instant startDate,
        final Instant endDate
    ) throws IOException, NoSuchAlgorithmException, OperatorCreationException {
        return generateCaCertificate(parentKeyPair, subjectName, generateSerialNumber(), startDate, endDate);
    }

    public X509CertificateHolder generateCaCertificate(
        final KeyPair parentKeyPair,
        final BigInteger serialNumber,
        final Instant startDate,
        final Instant endDate
    ) throws IOException, NoSuchAlgorithmException, OperatorCreationException {
        return generateCaCertificate(parentKeyPair, DEFAULT_SUBJECT_NAME, serialNumber, startDate, endDate);
    }

    public X509CertificateHolder generateCaCertificate(
        final KeyPair parentKeyPair,
        final String subjectName,
        final BigInteger serialNumber,
        final Instant startDate,
        final Instant endDate
    ) throws IOException, NoSuchAlgorithmException, OperatorCreationException {
        // CS-SUPPRESS-SINGLE: RegexpSingleline Extension should only be used sparingly to keep implementations as generic as possible
        return createCertificateBuilder(
            subjectName,
            DEFAULT_SUBJECT_NAME,
            parentKeyPair.getPublic(),
            parentKeyPair.getPublic(),
            serialNumber,
            startDate,
            endDate
        ).addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
            .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign))
            .build(new JcaContentSignerBuilder("SHA256withRSA").setProvider(BOUNCY_CASTLE_PROVIDER).build(parentKeyPair.getPrivate()));
        // CS-ENFORCE-SINGLE
    }

    public Tuple<PrivateKey, X509CertificateHolder> generateAccessCertificate(final KeyPair parentKeyPair) throws NoSuchAlgorithmException,
        IOException, OperatorCreationException {
        final var startAndEndDate = generateStartAndEndDate();
        return generateAccessCertificate(
            DEFAULT_SUBJECT_NAME,
            DEFAULT_SUBJECT_NAME,
            parentKeyPair,
            generateSerialNumber(),
            startAndEndDate.v1(),
            startAndEndDate.v2(),
            defaultSubjectAlternativeNames()
        );
    }

    public Tuple<PrivateKey, X509CertificateHolder> generateAccessCertificate(final KeyPair parentKeyPair, final BigInteger serialNumber)
        throws NoSuchAlgorithmException, IOException, OperatorCreationException {
        final var startAdnEndDate = generateStartAndEndDate();
        return generateAccessCertificate(
            DEFAULT_SUBJECT_NAME,
            DEFAULT_SUBJECT_NAME,
            parentKeyPair,
            serialNumber,
            startAdnEndDate.v1(),
            startAdnEndDate.v2(),
            defaultSubjectAlternativeNames()
        );
    }

    public Tuple<PrivateKey, X509CertificateHolder> generateAccessCertificate(
        final KeyPair parentKeyPair,
        final Instant startDate,
        final Instant endDate
    ) throws NoSuchAlgorithmException, IOException, OperatorCreationException {
        return generateAccessCertificate(
            DEFAULT_SUBJECT_NAME,
            DEFAULT_SUBJECT_NAME,
            parentKeyPair,
            generateSerialNumber(),
            startDate,
            endDate,
            defaultSubjectAlternativeNames()
        );
    }

    public Tuple<PrivateKey, X509CertificateHolder> generateAccessCertificate(
        final KeyPair parentKeyPair,
        final Instant startDate,
        final Instant endDate,
        List<ASN1Encodable> sans
    ) throws NoSuchAlgorithmException, IOException, OperatorCreationException {
        return generateAccessCertificate(
            DEFAULT_SUBJECT_NAME,
            DEFAULT_SUBJECT_NAME,
            parentKeyPair,
            generateSerialNumber(),
            startDate,
            endDate,
            sans
        );
    }

    public Tuple<PrivateKey, X509CertificateHolder> generateAccessCertificate(
        final KeyPair parentKeyPair,
        final String subject,
        final String issuer
    ) throws NoSuchAlgorithmException, IOException, OperatorCreationException {
        final var startAndEndDate = generateStartAndEndDate();
        return generateAccessCertificate(
            subject,
            issuer,
            parentKeyPair,
            generateSerialNumber(),
            startAndEndDate.v1(),
            startAndEndDate.v2(),
            defaultSubjectAlternativeNames()
        );
    }

    public Tuple<PrivateKey, X509CertificateHolder> generateAccessCertificate(final KeyPair parentKeyPair, final List<ASN1Encodable> sans)
        throws NoSuchAlgorithmException, IOException, OperatorCreationException {
        final var startAndEndDate = generateStartAndEndDate();
        return generateAccessCertificate(
            DEFAULT_SUBJECT_NAME,
            DEFAULT_SUBJECT_NAME,
            parentKeyPair,
            generateSerialNumber(),
            startAndEndDate.v1(),
            startAndEndDate.v2(),
            sans
        );
    }

    public Tuple<PrivateKey, X509CertificateHolder> generateAccessCertificate(
        final String subject,
        final String issuer,
        final KeyPair parentKeyPair,
        final BigInteger serialNumber,
        final Instant startDate,
        final Instant endDate,
        final List<ASN1Encodable> sans
    ) throws NoSuchAlgorithmException, IOException, OperatorCreationException {
        final var keyPair = generateKeyPair();
        // CS-SUPPRESS-SINGLE: RegexpSingleline Extension should only be used sparingly to keep implementations as generic as possible
        final var certificate = createCertificateBuilder(
            subject,
            issuer,
            keyPair.getPublic(),
            parentKeyPair.getPublic(),
            serialNumber,
            startDate,
            endDate
        ).addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
            .addExtension(
                Extension.keyUsage,
                true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.keyEncipherment)
            )
            .addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth))
            .addExtension(Extension.subjectAlternativeName, false, new DERSequence(sans.toArray(sans.toArray(new ASN1Encodable[0]))))
            .build(new JcaContentSignerBuilder("SHA256withRSA").setProvider(BOUNCY_CASTLE_PROVIDER).build(parentKeyPair.getPrivate()));
        // CS-ENFORCE-SINGLE
        return Tuple.tuple(keyPair.getPrivate(), certificate);
    }

    private List<ASN1Encodable> defaultSubjectAlternativeNames() {
        return List.of(
            new GeneralName(GeneralName.registeredID, "1.2.3.4.5.5"),
            new GeneralName(GeneralName.dNSName, "localhost"),
            new GeneralName(GeneralName.iPAddress, "127.0.0.1")
        );
    }

    public X509Certificate toX509Certificate(final X509CertificateHolder x509CertificateHolder) throws CertificateException {
        return new JcaX509CertificateConverter().getCertificate(x509CertificateHolder);
    }

    private X509v3CertificateBuilder createCertificateBuilder(
        final String subject,
        final String issuer,
        final PublicKey certificatePublicKey,
        final PublicKey parentPublicKey,
        final BigInteger serialNumber,
        final Instant startDate,
        final Instant endDate
    ) throws NoSuchAlgorithmException, CertIOException {
        // CS-SUPPRESS-SINGLE: RegexpSingleline Extension should only be used sparingly to keep implementations as generic as possible
        final var subjectName = new X500Name(RFC4519Style.INSTANCE, subject);
        final var issuerName = new X500Name(RFC4519Style.INSTANCE, issuer);
        final var extUtils = new JcaX509ExtensionUtils();
        return new X509v3CertificateBuilder(
            issuerName,
            serialNumber,
            Date.from(startDate),
            Date.from(endDate),
            subjectName,
            SubjectPublicKeyInfo.getInstance(certificatePublicKey.getEncoded())
        ).addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(parentPublicKey))
            .addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(certificatePublicKey));
        // CS-ENFORCE-SINGLE
    }

    Tuple<Instant, Instant> generateStartAndEndDate() {
        final var startDate = Instant.now().minusMillis(24 * 3600 * 1000);
        final var endDate = Instant.from(startDate).plus(10, ChronoUnit.DAYS);
        return Tuple.tuple(startDate, endDate);
    }

    public BigInteger generateSerialNumber() {
        return BigInteger.valueOf(Instant.now().plusMillis(100).getEpochSecond());
    }

}
