/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
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

import org.elasticsearch.action.Action;
import org.elasticsearch.client.ElasticsearchClient;

public class LicenseInfoAction extends Action<LicenseInfoRequest, LicenseInfoResponse, LicenseInfoRequestBuilder> {

    public static final LicenseInfoAction INSTANCE = new LicenseInfoAction();
    public static final String NAME = "cluster:admin/searchguard/license/info";

    protected LicenseInfoAction() {
        super(NAME);
    }

    @Override
    public LicenseInfoRequestBuilder newRequestBuilder(final ElasticsearchClient client) {
        return new LicenseInfoRequestBuilder(client, this);
    }

    @Override
    public LicenseInfoResponse newResponse() {
        return new LicenseInfoResponse();
    }

}
