/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources;

import static org.opensearch.index.seqno.SequenceNumbers.UNASSIGNED_PRIMARY_TERM;
import static org.opensearch.index.seqno.SequenceNumbers.UNASSIGNED_SEQ_NO;

/**
 * A resource document's version, which the {@code all_shared_principals} write is guarded by.
 *
 * @param seqNo       the document's sequence number
 * @param primaryTerm the primary term of that sequence number
 */
public record ResourceVersion(long seqNo, long primaryTerm) {

    /** No version is held, so the write reads it first. */
    public static final ResourceVersion UNKNOWN = new ResourceVersion(UNASSIGNED_SEQ_NO, UNASSIGNED_PRIMARY_TERM);

    /**
     * @return whether a write can start from this version without reading it
     */
    public boolean isKnown() {
        return seqNo != UNASSIGNED_SEQ_NO;
    }
}
