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

package org.opensearch.security.auth.http.jwt.keybyoidc;

import java.util.Collections;

import org.junit.Assert;
import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class JwtVerifierTest {

    @Test
    public void wrongIssuerWithKnownKidIsRejectedBeforeKeyLookup() throws Exception {
        KeyProvider keyProvider = mock(KeyProvider.class);
        when(keyProvider.getKey(any())).thenReturn(TestJwk.RSA_1_PUBLIC);

        assertInvalidIssuer(keyProvider, TestJwts.MC_COY_SIGNED_RSA_1);
        verify(keyProvider, never()).getKey(any());
    }

    @Test
    public void wrongIssuerWithUnknownKidIsRejectedBeforeKeyLookup() throws Exception {
        KeyProvider keyProvider = mock(KeyProvider.class);
        when(keyProvider.getKey(any())).thenThrow(new BadCredentialsException("Unknown kid kid/1"));

        assertInvalidIssuer(keyProvider, TestJwts.MC_COY_SIGNED_RSA_1);
        verify(keyProvider, never()).getKey(any());
        verify(keyProvider, never()).getKeyAfterRefresh(any());
    }

    @Test
    public void missingIssuerIsRejectedBeforeKeyLookup() throws Exception {
        KeyProvider keyProvider = mock(KeyProvider.class);
        when(keyProvider.getKey(any())).thenReturn(TestJwk.RSA_1_PUBLIC);
        String tokenWithoutIssuer = TestJwts.createSigned(TestJwts.MC_COY_NO_ISSUER, TestJwk.RSA_1);

        assertInvalidIssuer(keyProvider, tokenWithoutIssuer);
        verify(keyProvider, never()).getKey(any());
    }

    private static void assertInvalidIssuer(KeyProvider keyProvider, String token) {
        JwtVerifier verifier = new JwtVerifier(keyProvider, 30, "OtherIssuer", Collections.emptyList());
        BadCredentialsException e = Assert.assertThrows(BadCredentialsException.class, () -> verifier.getVerifiedJwtToken(token));
        assertThat(e.getMessage(), is("Invalid issuer"));
    }
}
