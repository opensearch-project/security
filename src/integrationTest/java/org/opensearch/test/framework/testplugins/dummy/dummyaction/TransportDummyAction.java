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

package org.opensearch.test.framework.testplugins.dummy.dummyaction;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

public class TransportDummyAction extends HandledTransportAction<DummyRequest, DummyResponse> {

    @Inject
    public TransportDummyAction(final TransportService transportService, final ActionFilters actionFilters) {
        super(DummyAction.NAME, transportService, actionFilters, DummyRequest::new);
    }

    @Override
    protected void doExecute(Task task, DummyRequest request, ActionListener<DummyResponse> listener) {
        String responseString = "Hello from dummy plugin";
        listener.onResponse(new DummyResponse(responseString));
    }
}
