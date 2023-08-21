/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

package org.opensearch.test.framework.testplugins.dummyprotected.dummyaction;

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
        String responseString = "Hello from dummy protected plugin";

        listener.onResponse(new DummyResponse(responseString));
    }
}
