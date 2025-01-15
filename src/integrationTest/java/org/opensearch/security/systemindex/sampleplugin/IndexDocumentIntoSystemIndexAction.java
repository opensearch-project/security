/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */

package org.opensearch.security.systemindex.sampleplugin;

import org.opensearch.action.ActionType;
// CS-SUPPRESS-SINGLE: RegexpSingleline It is not possible to use phrase "cluster manager" instead of master here
import org.opensearch.action.support.master.AcknowledgedResponse;
// CS-ENFORCE-SINGLE

public class IndexDocumentIntoSystemIndexAction extends ActionType<AcknowledgedResponse> {
    public static final IndexDocumentIntoSystemIndexAction INSTANCE = new IndexDocumentIntoSystemIndexAction();
    public static final String NAME = "mock:systemindex/index";

    private IndexDocumentIntoSystemIndexAction() {
        super(NAME, AcknowledgedResponse::new);
    }
}
