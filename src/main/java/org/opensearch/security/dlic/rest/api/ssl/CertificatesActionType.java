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

import org.opensearch.action.ActionType;

public class CertificatesActionType extends ActionType<CertificatesNodesResponse> {

    public static final CertificatesActionType INSTANCE = new CertificatesActionType();

    public static final String NAME = "cluster:admin/security/certificates/info";

    public CertificatesActionType() {
        super(NAME, CertificatesNodesResponse::new);
    }
}
