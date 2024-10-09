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

package org.opensearch.security.ssl.config;

import java.lang.reflect.Method;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;

public class Certificate {

    private final static Logger LOGGER = LogManager.getLogger(Certificate.class);

    private final X509Certificate certificate;

    private final String format;

    private final String alias;

    private final boolean hasKey;

    public Certificate(final X509Certificate certificate, final boolean hasKey) {
        this(certificate, "pem", null, hasKey);
    }

    public Certificate(final X509Certificate certificate, final String format, final String alias, final boolean hasKey) {
        this.certificate = certificate;
        this.format = format;
        this.alias = alias;
        this.hasKey = hasKey;
    }

    public X509Certificate x509Certificate() {
        return certificate;
    }

    public String format() {
        return format;
    }

    public String alias() {
        return alias;
    }

    public boolean hasKey() {
        return hasKey;
    }

    public String subjectAlternativeNames() {
        return loadSubjectAlternativeNames();
    }

    @Deprecated(since = "since JDK 21", forRemoval = true)
    public String loadSubjectAlternativeNames() {
        String san = "";
        try {
            Collection<List<?>> altNames = certificate != null && certificate.getSubjectAlternativeNames() != null
                ? certificate.getSubjectAlternativeNames()
                : null;
            if (altNames != null) {
                Comparator<List<?>> comparator = Comparator.comparing((List<?> altName) -> (Integer) altName.get(0))
                    .thenComparing((List<?> altName) -> (String) altName.get(1));

                Set<List<?>> sans = new TreeSet<>(comparator);
                for (List<?> altName : altNames) {
                    Integer type = (Integer) altName.get(0);
                    // otherName requires parsing to string
                    if (type == 0) {
                        List<?> otherName = parseOtherName(altName);
                        if (otherName != null) {
                            sans.add(Arrays.asList(type, otherName));
                        }
                    } else {
                        sans.add(altName);
                    }
                }
                san = sans.toString();
            }
        } catch (CertificateParsingException e) {
            LOGGER.error("Issue parsing SubjectAlternativeName:", e);
        }

        return san;
    }

    @Deprecated(since = "since JDK 21", forRemoval = true)
    private List<String> parseOtherName(List<?> altName) {
        if (altName.size() < 2) {
            LOGGER.warn("Couldn't parse subject alternative names");
            return null;
        }
        try (final ASN1InputStream in = new ASN1InputStream((byte[]) altName.get(1))) {
            final ASN1Primitive asn1Primitive = in.readObject();
            final ASN1Sequence sequence = ASN1Sequence.getInstance(asn1Primitive);
            final ASN1ObjectIdentifier asn1ObjectIdentifier = ASN1ObjectIdentifier.getInstance(sequence.getObjectAt(0));
            final ASN1TaggedObject asn1TaggedObject = ASN1TaggedObject.getInstance(sequence.getObjectAt(1));
            Method getObjectMethod = getObjectMethod();
            ASN1Object maybeTaggedAsn1Primitive = (ASN1Primitive) getObjectMethod.invoke(asn1TaggedObject);
            if (maybeTaggedAsn1Primitive instanceof ASN1TaggedObject) {
                maybeTaggedAsn1Primitive = (ASN1Primitive) getObjectMethod.invoke(maybeTaggedAsn1Primitive);
            }
            if (maybeTaggedAsn1Primitive instanceof ASN1String) {
                return ImmutableList.of(asn1ObjectIdentifier.getId(), maybeTaggedAsn1Primitive.toString());
            } else {
                LOGGER.warn("Couldn't parse subject alternative names");
                return null;
            }
        } catch (final Exception ioe) { // catch all exception here since BC throws diff exceptions
            throw new RuntimeException("Couldn't parse subject alternative names", ioe);
        }
    }

    static Method getObjectMethod() throws ClassNotFoundException, NoSuchMethodException {
        Class<?> asn1TaggedObjectClass = Class.forName("org.bouncycastle.asn1.ASN1TaggedObject");
        try {
            return asn1TaggedObjectClass.getMethod("getBaseObject");
        } catch (NoSuchMethodException ex) {
            return asn1TaggedObjectClass.getMethod("getObject");
        }
    }

    public String serialNumber() {
        return certificate.getSerialNumber().toString();
    }

    public String subject() {
        return certificate.getSubjectX500Principal() != null ? certificate.getSubjectX500Principal().getName() : null;
    }

    public String issuer() {
        return certificate.getIssuerX500Principal() != null ? certificate.getIssuerX500Principal().getName() : null;
    }

    public String notAfter() {
        return certificate.getNotAfter() != null ? certificate.getNotAfter().toInstant().toString() : null;
    }

    public String notBefore() {
        return certificate.getNotBefore() != null ? certificate.getNotBefore().toInstant().toString() : null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Certificate that = (Certificate) o;
        return hasKey == that.hasKey
            && Objects.equals(certificate, that.certificate)
            && Objects.equals(format, that.format)
            && Objects.equals(alias, that.alias);
    }

    @Override
    public int hashCode() {
        return Objects.hash(certificate, format, alias, hasKey);
    }

    @Override
    public String toString() {
        return "Certificate{" + "format='" + format + '\'' + ", alias='" + alias + '\'' + ", hasKey=" + hasKey + '}';
    }
}
