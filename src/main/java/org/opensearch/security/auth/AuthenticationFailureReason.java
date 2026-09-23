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

package org.opensearch.security.auth;

/**
 * Structured reason for a failed authentication attempt.
 *
 * <p>Values are surfaced in audit events via
 * {@link org.opensearch.security.auditlog.impl.AuditMessage#AUTHENTICATION_FAILURE_REASON}
 * so investigators can distinguish authentication rejection modes without parsing
 * free-form log messages. New values MUST NOT change the meaning of existing values;
 * add new entries for new rejection paths.</p>
 */
public enum AuthenticationFailureReason {

    /**
     * The credential presented a subject that used a prefix reserved for internal
     * security identities (for example the {@code plugin:} or {@code token:} prefixes).
     */
    RESERVED_SUBJECT_PREFIX
}
