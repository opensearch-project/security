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

import org.opensearch.action.support.nodes.BaseNodesRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

public class CertificatesInfoNodesRequest extends BaseNodesRequest<CertificatesInfoNodesRequest> {

    private final CertificateType certificateType;

    private final boolean inMemory;

    public CertificatesInfoNodesRequest(CertificateType certificateType, boolean inMemory, String... nodesIds) {
        super(nodesIds);
        this.certificateType = certificateType;
        this.inMemory = inMemory;
    }

    public CertificatesInfoNodesRequest(final StreamInput in) throws IOException {
        super(in);
        certificateType = in.readEnum(CertificateType.class);
        inMemory = in.readBoolean();
    }

    public CertificateType certificateType() {
        return certificateType;
    }

    public boolean inMemory() {
        return inMemory;
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeEnum(certificateType);
        out.writeBoolean(inMemory);
    }
}
