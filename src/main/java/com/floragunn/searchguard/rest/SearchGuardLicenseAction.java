/*
 * Copyright 2017 floragunn GmbH
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

package com.floragunn.searchguard.rest;

import static org.elasticsearch.rest.RestRequest.Method.GET;
import static org.elasticsearch.rest.RestRequest.Method.POST;

import java.io.IOException;

import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.rest.action.RestActions.NodesResponseRestListener;
import org.elasticsearch.threadpool.ThreadPool;

import com.floragunn.searchguard.action.licenseinfo.LicenseInfoAction;
import com.floragunn.searchguard.action.licenseinfo.LicenseInfoNodeResponse;
import com.floragunn.searchguard.action.licenseinfo.LicenseInfoRequest;
import com.floragunn.searchguard.action.licenseinfo.LicenseInfoResponse;
import com.floragunn.searchguard.configuration.IndexBaseConfigurationRepository;
import com.floragunn.searchguard.configuration.PrivilegesEvaluator;

public class SearchGuardLicenseAction extends BaseRestHandler {

    public SearchGuardLicenseAction(final Settings settings
            , final RestController controller
) {
        super(settings);
        controller.registerHandler(GET, "/_searchguard/license", this);
        controller.registerHandler(POST, "/_searchguard/license", this);
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        LicenseInfoRequest licenseInfoRequest = new LicenseInfoRequest();
        return channel -> client.executeLocally(LicenseInfoAction.INSTANCE, licenseInfoRequest, new NodesResponseRestListener<>(channel));
    }
}
