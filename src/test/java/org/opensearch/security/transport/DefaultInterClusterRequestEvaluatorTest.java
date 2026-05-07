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

package org.opensearch.security.transport;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.transport.TransportRequest;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DefaultInterClusterRequestEvaluatorTest {

    private static final String NODE_OID = "1.2.3.4.5.5";

    private DefaultInterClusterRequestEvaluator newEvaluator() {
        Settings settings = Settings.builder().put(ConfigConstants.SECURITY_CERT_OID, NODE_OID).build();
        return new DefaultInterClusterRequestEvaluator(settings);
    }

    @Test
    public void testIsInterClusterRequest_upnOtherNameInSan_doesNotThrow() throws Exception {
        // Reproduces issue #6090: certs issued by Windows CA contain a UPN otherName SAN entry
        // (OID 1.3.6.1.4.1.311.20.2.3). Java surfaces such entries as a List with size > 2, where
        // the third element is the OID String. The previous iterator-based parser tried to cast
        // the OID String to int on the next loop iteration, throwing ClassCastException.
        X509Certificate cert = mock(X509Certificate.class);
        List<List<?>> sanList = new ArrayList<>();
        // otherName SAN: [typeId=0, value (parsed), oid (String)]
        sanList.add(Arrays.asList(0, "user@example.com", "1.3.6.1.4.1.311.20.2.3"));
        when(cert.getSubjectAlternativeNames()).thenReturn(sanList);

        DefaultInterClusterRequestEvaluator evaluator = newEvaluator();
        boolean result = evaluator.isInterClusterRequest(
            mock(TransportRequest.class),
            new X509Certificate[] { cert },
            new X509Certificate[] { cert },
            "CN=foo"
        );

        assertFalse(result);
    }

    @Test
    public void testIsInterClusterRequest_oidSanMatchesNodeOid_returnsTrue() throws Exception {
        X509Certificate cert = mock(X509Certificate.class);
        List<List<?>> sanList = new ArrayList<>();
        // registeredID SAN (typeId=8) — value is the OID as String
        sanList.add(Arrays.asList(8, NODE_OID));
        when(cert.getSubjectAlternativeNames()).thenReturn(sanList);

        DefaultInterClusterRequestEvaluator evaluator = newEvaluator();
        boolean result = evaluator.isInterClusterRequest(
            mock(TransportRequest.class),
            new X509Certificate[] { cert },
            new X509Certificate[] { cert },
            "CN=foo"
        );

        assertTrue(result);
    }

    @Test
    public void testIsInterClusterRequest_oidSanAlongsideUpn_returnsTrue() throws Exception {
        // Mixed SAN list: UPN otherName + matching node OID. Must not throw and must still match.
        X509Certificate cert = mock(X509Certificate.class);
        List<List<?>> sanList = new ArrayList<>();
        sanList.add(Arrays.asList(0, "user@example.com", "1.3.6.1.4.1.311.20.2.3"));
        sanList.add(Arrays.asList(2, "node1.example.com"));
        sanList.add(Arrays.asList(8, NODE_OID));
        when(cert.getSubjectAlternativeNames()).thenReturn(sanList);

        DefaultInterClusterRequestEvaluator evaluator = newEvaluator();
        boolean result = evaluator.isInterClusterRequest(
            mock(TransportRequest.class),
            new X509Certificate[] { cert },
            new X509Certificate[] { cert },
            "CN=foo"
        );

        assertTrue(result);
    }

    @Test
    public void testIsInterClusterRequest_nullSan_returnsFalse() throws Exception {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getSubjectAlternativeNames()).thenReturn(null);

        DefaultInterClusterRequestEvaluator evaluator = newEvaluator();
        boolean result = evaluator.isInterClusterRequest(
            mock(TransportRequest.class),
            new X509Certificate[] { cert },
            new X509Certificate[] { cert },
            "CN=foo"
        );

        assertFalse(result);
    }
}
