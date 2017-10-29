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
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.elasticsearch.action.FailedNodeException;
import org.elasticsearch.action.support.nodes.BaseNodesResponse;
import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;

import com.floragunn.searchguard.configuration.SearchGuardLicense;
import com.floragunn.searchguard.support.ModuleInfo;
import com.floragunn.searchguard.support.ModuleType;

public class LicenseInfoResponse extends BaseNodesResponse<LicenseInfoNodeResponse> implements ToXContent {
    
    public LicenseInfoResponse() {
    }
    
    public LicenseInfoResponse(final ClusterName clusterName, List<LicenseInfoNodeResponse> nodes, List<FailedNodeException> failures) {
        super(clusterName, nodes, failures);   
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
        
        final List<LicenseInfoNodeResponse> allNodes = getNodes();
        
        if(allNodes.isEmpty()) {
            throw new IOException("All nodes failed");
        }
        
        final List<LicenseInfoNodeResponse> nonNullLicenseNodes = allNodes.stream().filter(r->r != null && r.getLicense() != null).collect(Collectors.toList());
        
        builder.startObject("sg_license");   
        
        if(nonNullLicenseNodes.size() != allNodes.size() && nonNullLicenseNodes.size() > 0) {
            
            final SearchGuardLicense license = nonNullLicenseNodes.get(0).getLicense();
            
            builder.field("uid", license.getUid());
            builder.field("type", license.getType());
            builder.field("issue_date", license.getIssueDate());
            builder.field("expiry_date", license.getExpiryDate());
            builder.field("issued_to", license.getIssuedTo());
            builder.field("issuer", license.getIssuer());
            builder.field("start_date", license.getStartDate());
            builder.field("major_version", license.getMajorVersion());
            builder.field("cluster_name", license.getClusterName());
            builder.field("msgs", new String[]{"License mismatch across some nodes"});
            builder.field("expiry_in_days", license.getExpiresInDays());
            builder.field("is_expired", license.isExpired());
            builder.field("is_valid", false);
            builder.field("action", "Enable or disable enterprise modules on all your nodes");
            builder.field("prod_usage", "No");
            builder.field("license_required", true);
            builder.field("allowed_node_count_per_cluster", license.getAllowedNodeCount() > 1500?"unlimited":String.valueOf(license.getAllowedNodeCount()));
            
        } else if (nonNullLicenseNodes.size() == 0) {
            builder.field("msgs", new String[]{"No license required because enterprise modules not enabled."});
            builder.field("license_required", false);
        } else {
            
            final SearchGuardLicense license = nonNullLicenseNodes.get(0).getLicense();
                 
            builder.field("uid", license.getUid());
            builder.field("type", license.getType());
            builder.field("issue_date", license.getIssueDate());
            builder.field("expiry_date", license.getExpiryDate());
            builder.field("issued_to", license.getIssuedTo());
            builder.field("issuer", license.getIssuer());
            builder.field("start_date", license.getStartDate());
            builder.field("major_version", license.getMajorVersion());
            builder.field("cluster_name", license.getClusterName());
            builder.field("msgs", license.getMsgs());
            builder.field("expiry_in_days", license.getExpiresInDays());
            builder.field("is_expired", license.isExpired());
            builder.field("is_valid", license.isValid());
            builder.field("action", license.getAction());
            builder.field("prod_usage", license.getProdUsage());
            builder.field("license_required", true);
            builder.field("allowed_node_count_per_cluster", license.getAllowedNodeCount() > 1500?"unlimited":String.valueOf(license.getAllowedNodeCount()));
        }
        
        builder.endObject();
        
        builder.startObject("modules");
        
        List<ModuleInfo> mod0 = new LinkedList<>(allNodes.get(0).getModules());
        
        for(ModuleInfo moduleInfo: mod0) {
        	ModuleType type = moduleInfo.getModuleType();
        	Map<String, String> infoAsMap = moduleInfo.getAsMap();
            builder.field(type.name(), infoAsMap);
        }
        
        boolean mismatch = false;
        List<String> mismatchedNodes = new LinkedList<>();
        for(LicenseInfoNodeResponse node: allNodes) {
        	for(ModuleInfo nodeModuleInfo : node.getModules()) {
        		if (!mod0.contains(nodeModuleInfo)) {
        			mismatch = true;
        			mismatchedNodes.add(node.getNode().getName());
        			break;
        		}
        	}
        }

        builder.endObject();
        
        builder.startObject("compatibility");
        builder.field("modules_mismatch", mismatch);
        if (mismatch) {
        	builder.field("mismatched_nodes", mismatchedNodes);
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
