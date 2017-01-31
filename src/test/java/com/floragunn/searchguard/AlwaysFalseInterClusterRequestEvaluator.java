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

package com.floragunn.searchguard;

import java.security.cert.X509Certificate;

import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.transport.TransportRequest;

import com.floragunn.searchguard.transport.InterClusterRequestEvaluator;


public class AlwaysFalseInterClusterRequestEvaluator implements InterClusterRequestEvaluator {

    public AlwaysFalseInterClusterRequestEvaluator(Settings settings) {
        super();
    }

    @Override
    public boolean isInterClusterRequest(TransportRequest request, X509Certificate[] localCerts, X509Certificate[] peerCerts,
            String principal) {
        return false;
    }

}
