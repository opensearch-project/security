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

package org.opensearch.security.action.configupdate;

import org.opensearch.action.ActionType;
import org.opensearch.action.support.nodes.NodesOperationRequestBuilder;
import org.opensearch.client.OpenSearchClient;

public class ConfigUpdateRequestBuilder extends
NodesOperationRequestBuilder<ConfigUpdateRequest, ConfigUpdateResponse, ConfigUpdateRequestBuilder> {

    protected ConfigUpdateRequestBuilder(OpenSearchClient client, ActionType<ConfigUpdateResponse> action) {
        super(client, action, new ConfigUpdateRequest());
    }

    public ConfigUpdateRequestBuilder setShardId(final String[] configTypes) {
        request.setConfigTypes(configTypes);
        return this;
    }
}
