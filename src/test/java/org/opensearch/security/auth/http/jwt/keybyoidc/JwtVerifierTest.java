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
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;

import com.nimbusds.jwt.SignedJWT;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
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

    @Test
    public void missingExpIsRejectedWhenRequired() throws Exception {
        JwtVerifier verifier = verifierRequiring("exp");

        BadCredentialsException e = Assert.assertThrows(
            BadCredentialsException.class,
            () -> verifier.getVerifiedJwtToken(TestJwts.MC_COY_SIGNED_RSA_1)
        );
        assertThat(e.getMessage(), containsString("exp"));
    }

    @Test
    public void missingNbfIsRejectedWhenRequired() throws Exception {
        JwtVerifier verifier = verifierRequiring("nbf");

        BadCredentialsException e = Assert.assertThrows(
            BadCredentialsException.class,
            () -> verifier.getVerifiedJwtToken(TestJwts.MC_COY_WITH_EXP_ONLY_SIGNED_RSA_1)
        );
        assertThat(e.getMessage(), containsString("nbf"));
    }

    @Test
    public void presentExpAndNbfAreAcceptedWhenRequired() throws Exception {
        JwtVerifier verifier = verifierRequiring("exp", "nbf");

        SignedJWT jwt = verifier.getVerifiedJwtToken(TestJwts.MC_COY_WITH_EXP_AND_NBF_SIGNED_RSA_1);

        assertThat(jwt.getJWTClaimsSet().getSubject(), is(TestJwts.MCCOY_SUBJECT));
    }

    @Test
    public void signatureIsVerifiedBeforeRequiredClaims() throws Exception {
        KeyProvider keyProvider = mock(KeyProvider.class);
        when(keyProvider.getKey(any())).thenReturn(TestJwk.RSA_2_PUBLIC); // wrong key for an RSA_1-signed token
        JwtVerifier verifier = new JwtVerifier(keyProvider, 30, null, Collections.emptyList(), Set.of("exp", "nbf"));

        BadCredentialsException e = Assert.assertThrows(
            BadCredentialsException.class,
            () -> verifier.getVerifiedJwtToken(TestJwts.MC_COY_SIGNED_RSA_1) // also has no exp/nbf
        );
        assertThat(e.getMessage(), is("Invalid JWT signature"));
    }

    @Test
    public void nullValuedExpIsRejectedWhenRequired() throws Exception {
        JwtVerifier verifier = verifierRequiring("exp");
        String token = TestJwts.createSignedWithRawPayload("{\"sub\":\"Leonard McCoy\",\"exp\":null}", TestJwk.RSA_1);

        BadCredentialsException e = Assert.assertThrows(BadCredentialsException.class, () -> verifier.getVerifiedJwtToken(token));
        assertThat(e.getMessage(), containsString("exp"));
    }

    @Test
    public void nullValuedNbfIsRejectedWhenRequired() throws Exception {
        JwtVerifier verifier = verifierRequiring("nbf");
        String token = TestJwts.createSignedWithRawPayload("{\"sub\":\"Leonard McCoy\",\"nbf\":null}", TestJwk.RSA_1);

        BadCredentialsException e = Assert.assertThrows(BadCredentialsException.class, () -> verifier.getVerifiedJwtToken(token));
        assertThat(e.getMessage(), containsString("nbf"));
    }

    @Test
    public void missingCustomClaimIsRejectedWhenRequired() throws Exception {
        JwtVerifier verifier = verifierRequiring("dept");

        BadCredentialsException e = Assert.assertThrows(
            BadCredentialsException.class,
            () -> verifier.getVerifiedJwtToken(TestJwts.MC_COY_SIGNED_RSA_1)
        );
        assertThat(e.getMessage(), containsString("dept"));
    }

    @Test
    public void nothingIsRequiredByDefault() throws Exception {
        KeyProvider keyProvider = mock(KeyProvider.class);
        when(keyProvider.getKey(any())).thenReturn(TestJwk.RSA_1_PUBLIC);
        JwtVerifier verifier = new JwtVerifier(keyProvider, 30, null, Collections.emptyList());

        Assert.assertNotNull(verifier.getVerifiedJwtToken(TestJwts.MC_COY_SIGNED_RSA_1));
    }

    @Test
    public void allNullValuedRequiredClaimsAreReported() throws Exception {
        JwtVerifier verifier = verifierRequiring("exp", "nbf");
        String token = TestJwts.createSignedWithRawPayload("{\"sub\":\"Leonard McCoy\",\"exp\":null,\"nbf\":null}", TestJwk.RSA_1);

        BadCredentialsException e = Assert.assertThrows(BadCredentialsException.class, () -> verifier.getVerifiedJwtToken(token));
        assertThat(e.getMessage(), containsString("exp"));
        assertThat(e.getMessage(), containsString("nbf"));
    }

    @Test
    public void findMissingClaimsReturnsEmptyListWhenNothingIsMissing() {
        assertThat(JwtVerifier.findMissingClaims(Set.of(), Map.of()), is(empty()));
        assertThat(JwtVerifier.findMissingClaims(Set.of("exp", "nbf"), Map.of("exp", 1, "nbf", 1, "sub", "a")), is(empty()));
    }

    @Test
    public void findMissingClaimsReturnsEveryMissingClaim() {
        assertThat(JwtVerifier.findMissingClaims(Set.of("exp", "nbf"), Map.of("exp", 1)), contains("nbf"));
        assertThat(JwtVerifier.findMissingClaims(Set.of("exp", "nbf", "sub"), Map.of("sub", "a")), containsInAnyOrder("exp", "nbf"));
    }

    @Test
    public void findMissingClaimsTreatsNullValueAsMissing() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("exp", null);

        assertThat(JwtVerifier.findMissingClaims(Set.of("exp"), claims), contains("exp"));
    }

    @Test
    public void readRequiredClaimsAcceptsListAndCommaSeparatedString() {
        Settings list = Settings.builder().putList("required_claims", "exp", "nbf").build();
        Settings string = Settings.builder().put("required_claims", "exp, nbf").build();

        assertThat(JwtVerifier.readRequiredClaims(list), is(Set.of("exp", "nbf")));
        assertThat(JwtVerifier.readRequiredClaims(string), is(Set.of("exp", "nbf")));
    }

    @Test
    public void readRequiredClaimsRequiresNothingWhenTheSettingIsMissing() {
        assertThat(JwtVerifier.readRequiredClaims(Settings.EMPTY), is(Set.of()));
    }

    @Test
    public void readRequiredClaimsRejectsMap() {
        Settings settings = Settings.builder().put("required_claims.exp", false).build();

        IllegalArgumentException e = Assert.assertThrows(IllegalArgumentException.class, () -> JwtVerifier.readRequiredClaims(settings));
        assertThat(e.getMessage(), containsString("must be a list"));
    }

    @Test
    public void readRequiredClaimsRejectsEmptyEntry() {
        Settings settings = Settings.builder().put("required_claims", "exp, ,nbf").build();

        IllegalArgumentException e = Assert.assertThrows(IllegalArgumentException.class, () -> JwtVerifier.readRequiredClaims(settings));
        assertThat(e.getMessage(), containsString("non-empty"));
    }

    private static JwtVerifier verifierRequiring(String... claims) throws Exception {
        KeyProvider keyProvider = mock(KeyProvider.class);
        when(keyProvider.getKey(any())).thenReturn(TestJwk.RSA_1_PUBLIC);
        return new JwtVerifier(keyProvider, 30, null, Collections.emptyList(), Set.of(claims));
    }
}
