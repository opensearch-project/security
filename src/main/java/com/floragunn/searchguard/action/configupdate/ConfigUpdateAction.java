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

package com.floragunn.searchguard.action.configupdate;

import org.elasticsearch.action.Action;
import org.elasticsearch.client.ElasticsearchClient;

public class ConfigUpdateAction extends Action<ConfigUpdateRequest, ConfigUpdateResponse, ConfigUpdateRequestBuilder> {

    public static final ConfigUpdateAction INSTANCE = new ConfigUpdateAction();
    public static final String NAME = "cluster:admin/searchguard/config/update";

    protected ConfigUpdateAction() {
        super(NAME);
    }

    @Override
    public ConfigUpdateRequestBuilder newRequestBuilder(final ElasticsearchClient client) {
        return new ConfigUpdateRequestBuilder(client, this);
    }

    @Override
    public ConfigUpdateResponse newResponse() {
        return new ConfigUpdateResponse();
    }

}
