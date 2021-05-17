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
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security;

import java.security.cert.X509Certificate;

import org.opensearch.common.settings.Settings;
import org.opensearch.transport.TransportRequest;

import com.amazon.opendistroforelasticsearch.security.transport.InterClusterRequestEvaluator;


public class AlwaysFalseInterClusterRequestEvaluator implements InterClusterRequestEvaluator {

    public AlwaysFalseInterClusterRequestEvaluator(Settings settings) {
        super();
    }

    @Override
    public boolean isInterClusterRequest(TransportRequest request, X509Certificate[] localCerts, X509Certificate[] peerCerts,
            String principal) {
        
        if(localCerts == null || peerCerts == null || principal == null
                || localCerts.length == 0 || peerCerts.length == 0 || principal.length() == 0) {
            return true;
        }
        
        return false;
    }

}
