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

package com.amazon.opendistroforelasticsearch.security.ssl;

import java.security.cert.X509Certificate;

import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;

public class TestPrincipalExtractor implements PrincipalExtractor {

    private static int transportCount = 0;
    private static int httpCount = 0;
    
    public TestPrincipalExtractor() {
    }

    @Override
    public String extractPrincipal(X509Certificate x509Certificate, Type type) {
        if(type == Type.HTTP) {
            httpCount++;
        }
        
        if(type == Type.TRANSPORT) {
            transportCount++;
        }
        
        return "testdn";
    }

    public static int getTransportCount() {
        return transportCount;
    }

    public static int getHttpCount() {
        return httpCount;
    }
    
    public static void reset() {
       httpCount = 0;
       transportCount = 0;
    }

}
