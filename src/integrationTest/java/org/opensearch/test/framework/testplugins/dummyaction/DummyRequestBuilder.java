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

package org.opensearch.test.framework.testplugins.dummyaction;

import org.opensearch.action.ActionRequestBuilder;
import org.opensearch.client.ClusterAdminClient;
import org.opensearch.client.OpenSearchClient;

import java.io.IOException;

public class DummyRequestBuilder extends ActionRequestBuilder<DummyRequest, DummyResponse> {
    public DummyRequestBuilder(final ClusterAdminClient client) throws IOException {
        this(client, DummyAction.INSTANCE);
    }

    public DummyRequestBuilder(final OpenSearchClient client, final DummyAction action) throws IOException {
        super(client, action, new DummyRequest());
    }
}
