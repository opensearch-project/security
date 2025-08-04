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

package org.opensearch.security.ssl.transport;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SPIFFEPrincipalExtractorTest {

    @Test
    public void testExtractSpiffePrincipal() throws Exception {
        X509Certificate cert = mock(X509Certificate.class);
        List<List<?>> sanList = new ArrayList<>();
        sanList.add(Arrays.asList(0, "otherName"));
        sanList.add(Arrays.asList(1, "rfc822Name"));
        sanList.add(Arrays.asList(2, "DNSName"));
        sanList.add(Arrays.asList(3, "x400Address"));
        sanList.add(Arrays.asList(4, "directoryName"));
        sanList.add(Arrays.asList(5, "ediPartyName"));
        sanList.add(Arrays.asList(6, "spiffe://example.org/test")); // uniformResourceIdentifier
        sanList.add(Arrays.asList(7, "IPAddress"));
        sanList.add(Arrays.asList(8, "registeredID"));
        when(cert.getSubjectAlternativeNames()).thenReturn(sanList);

        SPIFFEPrincipalExtractor extractor = new SPIFFEPrincipalExtractor();
        String principal = extractor.extractPrincipal(cert, PrincipalExtractor.Type.TRANSPORT);

        assertEquals("CN=spiffe://example.org/test", principal);
    }

    @Test
    public void testExtractPrincipal_noSpiffeUri() throws Exception {
        X509Certificate cert = mock(X509Certificate.class);
        List<List<?>> sanList = new ArrayList<>();
        sanList.add(Arrays.asList(6, "not-spiffe://example.org/test"));
        when(cert.getSubjectAlternativeNames()).thenReturn(sanList);

        SPIFFEPrincipalExtractor extractor = new SPIFFEPrincipalExtractor();
        String principal = extractor.extractPrincipal(cert, PrincipalExtractor.Type.TRANSPORT);

        assertNull(principal);
    }

    @Test
    public void testExtractPrincipal_nullCertificate() {
        SPIFFEPrincipalExtractor extractor = new SPIFFEPrincipalExtractor();
        assertNull(extractor.extractPrincipal(null, PrincipalExtractor.Type.TRANSPORT));
    }

    @Test
    public void testExtractPrincipal_nullSAN() throws Exception {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getSubjectAlternativeNames()).thenReturn(null);

        SPIFFEPrincipalExtractor extractor = new SPIFFEPrincipalExtractor();
        String principal = extractor.extractPrincipal(cert, PrincipalExtractor.Type.TRANSPORT);

        assertNull(principal);
    }

    @Test
    public void testExtractPrincipal_certificateParsingException() throws Exception {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getSubjectAlternativeNames()).thenThrow(new CertificateParsingException("bad"));

        SPIFFEPrincipalExtractor extractor = new SPIFFEPrincipalExtractor();
        String principal = extractor.extractPrincipal(cert, PrincipalExtractor.Type.TRANSPORT);

        assertNull(principal);
    }

    @Test
    public void testExtractPrincipal_sanItemNullAndTooShort() throws Exception {
        X509Certificate cert = mock(X509Certificate.class);

        List<List<?>> sanList = new ArrayList<>();
        sanList.add(null); // hits sanItem == null
        sanList.add(Arrays.asList(6)); // size < 2

        when(cert.getSubjectAlternativeNames()).thenReturn(sanList);

        SPIFFEPrincipalExtractor extractor = new SPIFFEPrincipalExtractor();
        String principal = extractor.extractPrincipal(cert, PrincipalExtractor.Type.TRANSPORT);

        assertNull(principal);
    }

    @Test
    public void testExtractPrincipal_altNameTypeNotIntegerOrValueNotString() throws Exception {
        X509Certificate cert = mock(X509Certificate.class);
        List<List<?>> sanList = new ArrayList<>();
        // altNameType is null
        sanList.add(Arrays.asList(null, "spiffe://example.org/test"));
        // altNameValue not a string
        sanList.add(Arrays.asList(6, 12345));
        when(cert.getSubjectAlternativeNames()).thenReturn(sanList);

        SPIFFEPrincipalExtractor extractor = new SPIFFEPrincipalExtractor();
        String principal = extractor.extractPrincipal(cert, PrincipalExtractor.Type.TRANSPORT);

        assertNull(principal);
    }
}
