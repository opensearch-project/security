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

package org.opensearch.security.user;

import org.junit.Test;

import org.opensearch.security.auth.AuthenticationFailureReason;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for {@link AuthCredentials#rejected(String, AuthenticationFailureReason)} and
 * the associated rejection accessors introduced for
 * {@code audit_request_attempted_user} / {@code audit_authentication_failure_reason}.
 */
public class AuthCredentialsTest {

    @Test
    public void rejectedFactoryPreservesAttemptedPrincipalAndReason() {
        final AuthCredentials creds = AuthCredentials.rejected(
            "plugin:reserved-subject",
            AuthenticationFailureReason.RESERVED_SUBJECT_PREFIX
        );

        assertTrue(creds.isRejected());
        assertFalse(creds.isComplete());
        assertThat(creds.getAttemptedPrincipal(), is("plugin:reserved-subject"));
        assertThat(creds.getFailureReason(), is(AuthenticationFailureReason.RESERVED_SUBJECT_PREFIX));
        // getUsername() returns the attempted principal so downstream code that logs the
        // username at MDC (e.g. BackendRegistry ThreadContext) does not observe null.
        assertThat(creds.getUsername(), is("plugin:reserved-subject"));
    }

    @Test
    public void rejectedFactoryRejectsNullAttemptedPrincipal() {
        assertThrows(
            IllegalArgumentException.class,
            () -> AuthCredentials.rejected(null, AuthenticationFailureReason.RESERVED_SUBJECT_PREFIX)
        );
    }

    @Test
    public void rejectedFactoryRejectsEmptyAttemptedPrincipal() {
        assertThrows(
            IllegalArgumentException.class,
            () -> AuthCredentials.rejected("", AuthenticationFailureReason.RESERVED_SUBJECT_PREFIX)
        );
    }

    @Test
    public void rejectedFactoryRejectsNullReason() {
        assertThrows(IllegalArgumentException.class, () -> AuthCredentials.rejected("subject", null));
    }

    @Test
    public void nonRejectedCredentialHasEmptyAttemptedPrincipalAndReason() {
        final AuthCredentials creds = new AuthCredentials("alice", new String[0]);

        assertFalse(creds.isRejected());
        assertThat(creds.getAttemptedPrincipal(), is(nullValue()));
        assertThat(creds.getFailureReason(), is(nullValue()));
    }

    @Test
    public void nonRejectedCredentialCanStillBeMarkedComplete() {
        final AuthCredentials creds = new AuthCredentials("alice", new String[0]).markComplete();

        assertTrue(creds.isComplete());
        assertFalse(creds.isRejected());
    }
}
