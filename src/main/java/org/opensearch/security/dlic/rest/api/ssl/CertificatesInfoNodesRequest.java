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

package org.opensearch.security.dlic.rest.api.ssl;

import java.io.IOException;
import java.util.Optional;

import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.nodes.BaseNodesRequest;
import org.opensearch.core.common.Strings;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.security.ssl.config.CertType;

public class CertificatesInfoNodesRequest extends BaseNodesRequest<CertificatesInfoNodesRequest> {

    private final String certificateType;

    private final boolean inMemory;

    public CertificatesInfoNodesRequest(String certificateType, boolean inMemory, String... nodesIds) {
        super(nodesIds);
        this.certificateType = certificateType;
        this.inMemory = inMemory;
    }

    public CertificatesInfoNodesRequest(final StreamInput in) throws IOException {
        super(in);
        certificateType = in.readOptionalString();
        inMemory = in.readBoolean();
    }

    public Optional<String> certificateType() {
        return Optional.ofNullable(certificateType);
    }

    public boolean inMemory() {
        return inMemory;
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeOptionalString(certificateType);
        out.writeBoolean(inMemory);
    }

    @Override
    public ActionRequestValidationException validate() {
        if (!Strings.isEmpty(certificateType) && !CertType.REGISTERED_CERT_TYPES.contains(certificateType)) {
            final var errorMessage = new ActionRequestValidationException();
            errorMessage.addValidationError(
                "wrong certificate type " + certificateType + ". Please use one of " + CertType.REGISTERED_CERT_TYPES
            );
            return errorMessage;
        }
        return super.validate();
    }
}
