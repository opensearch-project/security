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

import org.opensearch.Version;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.nodes.BaseNodesRequest;
import org.opensearch.core.common.Strings;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.security.ssl.config.CertType;

public class CertificatesInfoNodesRequest extends BaseNodesRequest<CertificatesInfoNodesRequest> {
    private final String certTypeID;
    private final boolean inMemory;

    public CertificatesInfoNodesRequest(String certTypeID, boolean inMemory, String... nodesIds) {
        super(nodesIds);
        this.certTypeID = certTypeID;
        this.inMemory = inMemory;
    }

    public CertificatesInfoNodesRequest(final StreamInput in) throws IOException {
        super(in);
        if (in.getVersion().before(Version.V_3_0_0)) {
            certTypeID = in.readEnum(CertificatesInfo.CertificateType_2_19.class).value();
        } else {
            certTypeID = in.readOptionalString();
        }
        inMemory = in.readBoolean();
    }

    public Optional<String> certificateType() {
        return Optional.ofNullable(certTypeID);
    }

    public boolean inMemory() {
        return inMemory;
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        super.writeTo(out);
        if (out.getVersion().before(Version.V_3_0_0)) {
            if (certTypeID == null) {
                out.writeEnum(CertificatesInfo.CertificateType_2_19.ALL);
            } else {
                out.writeEnum(CertificatesInfo.CertificateType_2_19.valueOf(certTypeID));
            }
        } else {
            out.writeOptionalString(certTypeID);
        }
        out.writeBoolean(inMemory);
    }

    @Override
    public ActionRequestValidationException validate() {
        if (!Strings.isEmpty(certTypeID) && !CertType.CERT_TYPE_REGISTRY.contains(certTypeID)) {
            final var errorMessage = new ActionRequestValidationException();
            errorMessage.addValidationError("wrong certificate type " + certTypeID + ". Please use one of " + CertType.CERT_TYPE_REGISTRY);
            return errorMessage;
        }
        return super.validate();
    }
}
