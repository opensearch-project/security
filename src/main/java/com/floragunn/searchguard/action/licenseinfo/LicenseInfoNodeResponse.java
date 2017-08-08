/*
 * Copyright 2015-2017 floragunn Gmbh
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
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import org.elasticsearch.action.support.nodes.BaseNodeResponse;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;

import com.floragunn.searchguard.configuration.SearchGuardLicense;

public class LicenseInfoNodeResponse extends BaseNodeResponse {
    
    private SearchGuardLicense license;
    
    LicenseInfoNodeResponse() {
    }

    public LicenseInfoNodeResponse(final DiscoveryNode node, SearchGuardLicense license) {
        super(node);
        this.license = license;
    }
    
    public static LicenseInfoNodeResponse readNodeResponse(StreamInput in) throws IOException {
        LicenseInfoNodeResponse nodeResponse = new LicenseInfoNodeResponse();
        nodeResponse.readFrom(in);
        return nodeResponse;
    }

    public SearchGuardLicense getLicense() {
        return license;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeOptionalWriteable(license);
    }

    @Override
    public void readFrom(StreamInput in) throws IOException {
        super.readFrom(in);
        license = in.readOptionalWriteable(SearchGuardLicense::new);
    }

    @Override
    public String toString() {
        return "LicenseInfoNodeResponse [license=" + license + "]";
    }
}
