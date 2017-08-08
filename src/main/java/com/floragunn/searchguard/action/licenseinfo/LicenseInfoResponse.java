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

import java.io.IOException;
import java.util.List;

import org.elasticsearch.action.FailedNodeException;
import org.elasticsearch.action.admin.cluster.node.stats.NodeStats;
import org.elasticsearch.action.support.nodes.BaseNodesResponse;
import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.ToXContent.Params;

import com.floragunn.searchguard.configuration.SearchGuardLicense;

public class LicenseInfoResponse extends BaseNodesResponse<LicenseInfoNodeResponse> implements ToXContent{

    private boolean overallValid = true;
    private boolean overallExpired = false;
    private int overallMinExpireDays = 0;
    
    public LicenseInfoResponse() {
    }
    
    public LicenseInfoResponse(final ClusterName clusterName, List<LicenseInfoNodeResponse> nodes, List<FailedNodeException> failures) {
        super(clusterName, nodes, failures);
        for (LicenseInfoNodeResponse nodeLic : getNodes()) {
            SearchGuardLicense license = nodeLic.getLicense();
            if(license == null) {
                overallValid = false;
                overallExpired = true;
                break;
            } else {
                license.isValid()
            }
        }
    }

    @Override
    public List<LicenseInfoNodeResponse> readNodesFrom(final StreamInput in) throws IOException {
        return in.readList(LicenseInfoNodeResponse::readNodeResponse);
    }

    @Override
    public void writeNodesTo(final StreamOutput out, List<LicenseInfoNodeResponse> nodes) throws IOException {
        out.writeStreamableList(nodes);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject("nodes");
        for (LicenseInfoNodeResponse nodeLic : getNodes()) {
            builder.startObject(nodeLic.getNode().getId());
            SearchGuardLicense license = nodeLic.getLicense();
            if(license == null) {
                builder.nullField("license");
            } else {
                nodeLic.getLicense().toXContent(builder, params);
            }
            builder.endObject();
        }
        builder.endObject();

        return builder;
    }

    @Override
    public String toString() {
        try {
            XContentBuilder builder = XContentFactory.jsonBuilder().prettyPrint();
            builder.startObject();
            toXContent(builder, EMPTY_PARAMS);
            builder.endObject();
            return builder.string();
        } catch (IOException e) {
            return "{ \"error\" : \"" + e.getMessage() + "\"}";
        }
    }
    
    
}
