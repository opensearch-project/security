/*
 * Copyright 2015-2017 floragunn GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.action.licenseinfo;

import org.elasticsearch.action.support.nodes.NodesOperationRequestBuilder;
import org.elasticsearch.client.ClusterAdminClient;
import org.elasticsearch.client.ElasticsearchClient;

public class LicenseInfoRequestBuilder extends
NodesOperationRequestBuilder<LicenseInfoRequest, LicenseInfoResponse, LicenseInfoRequestBuilder> {
    public LicenseInfoRequestBuilder(final ClusterAdminClient client) {
        this(client, LicenseInfoAction.INSTANCE);
    }

    public LicenseInfoRequestBuilder(final ElasticsearchClient client, final LicenseInfoAction action) {
        super(client, action, new LicenseInfoRequest());
    }
}
