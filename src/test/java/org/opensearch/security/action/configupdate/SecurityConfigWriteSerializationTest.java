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

package org.opensearch.security.action.configupdate;

import java.io.IOException;

import org.junit.Test;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.rest.RestStatus;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * Round-trip serialization coverage for {@link SecurityConfigWriteRequest} and
 * {@link SecurityConfigWriteResponse}. These are the two wire types added in issue #6337 and are
 * exercised end-to-end by {@code WaitForCompletionRestApiIntegrationTest}, but explicit
 * writeTo/readFrom tests here guard against silent wire-format regressions when either class picks
 * up a new field.
 */
public class SecurityConfigWriteSerializationTest {

    @Test
    public void requestRoundTripsAllFields() throws IOException {
        final IndexRequest indexRequest = new IndexRequest(".opendistro_security").id("roles")
            .setRefreshPolicy(RefreshPolicy.IMMEDIATE)
            .setIfSeqNo(42L)
            .setIfPrimaryTerm(7L)
            .source("roles", new BytesArray("{\"foo\":\"bar\"}"));

        final SecurityConfigWriteRequest original = new SecurityConfigWriteRequest(
            indexRequest,
            "roles",
            "roles/my_role",
            "'my_role' created.",
            RestStatus.CREATED
        );

        final SecurityConfigWriteRequest roundTripped;
        try (BytesStreamOutput out = new BytesStreamOutput()) {
            original.writeTo(out);
            try (StreamInput in = out.bytes().streamInput()) {
                roundTripped = new SecurityConfigWriteRequest(in);
            }
        }

        assertThat(roundTripped.getCType(), equalTo("roles"));
        assertThat(roundTripped.getDescription(), equalTo("roles/my_role"));
        assertThat(roundTripped.getSuccessMessage(), equalTo("'my_role' created."));
        assertThat(roundTripped.getSuccessStatus(), is(RestStatus.CREATED));

        final IndexRequest ir = roundTripped.getIndexRequest();
        assertThat(ir.index(), equalTo(".opendistro_security"));
        assertThat(ir.id(), equalTo("roles"));
        assertThat(ir.ifSeqNo(), is(42L));
        assertThat(ir.ifPrimaryTerm(), is(7L));
        assertThat(ir.getRefreshPolicy(), is(RefreshPolicy.IMMEDIATE));
    }

    @Test
    public void requestGetShouldStoreResultIsAlwaysTrue() {
        final SecurityConfigWriteRequest req = new SecurityConfigWriteRequest(
            new IndexRequest(".opendistro_security").id("roles"),
            "roles",
            "roles",
            "ok",
            RestStatus.OK
        );
        // Always true — see class-level Javadoc for why. Ensures the TaskManager stores the
        // result to .tasks so callers can poll GET /_tasks/{id} after completion.
        assertThat(req.getShouldStoreResult(), is(true));
    }

    @Test
    public void requestValidateRejectsMissingCType() {
        // Constructor uses Objects.requireNonNull so the empty-string case is what validate() has
        // to catch. This guards the transport-layer precondition path.
        final SecurityConfigWriteRequest req = new SecurityConfigWriteRequest(
            new IndexRequest(".opendistro_security").id("roles"),
            "",
            "",
            "ok",
            RestStatus.OK
        );
        assertThat(req.validate(), org.hamcrest.CoreMatchers.notNullValue());
    }

    @Test
    public void responseRoundTripsStatusAndMessage() throws IOException {
        final SecurityConfigWriteResponse original = new SecurityConfigWriteResponse(RestStatus.CREATED, "'my_role' created.");

        final SecurityConfigWriteResponse roundTripped;
        try (BytesStreamOutput out = new BytesStreamOutput()) {
            original.writeTo(out);
            try (StreamInput in = out.bytes().streamInput()) {
                roundTripped = new SecurityConfigWriteResponse(in);
            }
        }

        assertThat(roundTripped.getStatus(), is(RestStatus.CREATED));
        assertThat(roundTripped.getMessage(), equalTo("'my_role' created."));
    }
}
