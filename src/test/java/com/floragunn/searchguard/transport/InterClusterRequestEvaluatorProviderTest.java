/*
 * Copyright 2017 floragunn UG (haftungsbeschränkt)
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
package com.floragunn.searchguard.transport;

import static org.junit.Assert.*;

import java.security.cert.X509Certificate;

import org.elasticsearch.common.inject.Provider;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.Settings.Builder;
import org.elasticsearch.transport.TransportRequest;
import org.junit.Test;

public class InterClusterRequestEvaluatorProviderTest {

    private Settings settings;
    private Provider<InterClusterRequestEvaluator> provider;
    
    @Test
    public void testUsesDefaultWhenSettingIsMissing() {
        givenImplIs(null);
        provider = new InterClusterRequestEvaluatorProvider(settings);
        assertTrue("Exp. to use default evaluator when setting is missing", provider.get() instanceof DefaultInterClusterRequestEvaluator);
    }
    
    @Test
    public void testUsesDefaultWhenImplCantBeLoaded() {
        givenImplIs("java.lang.String");
        provider = new InterClusterRequestEvaluatorProvider(settings);
        assertTrue("Exp. to use default evaluator when implementation can not be loaded", provider.get() instanceof DefaultInterClusterRequestEvaluator);
    }

    @Test
    public void testLoadsCustomEvaluator() {
        givenImplIs(InterClusterRequestEvaluatorImpl.class.getName());
        provider = new InterClusterRequestEvaluatorProvider(settings);
        assertTrue("Exp. to use a custom evaluator when implementation is defined", provider.get() instanceof InterClusterRequestEvaluatorImpl);
    }
    
    private void givenImplIs(String name) {
        Builder builder = Settings.settingsBuilder();
        if(name != null) {
            builder.put(InterClusterRequestEvaluatorProvider.KEY, name);
        }
        settings = builder.build();
    }

    static class InterClusterRequestEvaluatorImpl implements InterClusterRequestEvaluator {

        public InterClusterRequestEvaluatorImpl(Settings settings) {
            
        }
        
        @Override
        public boolean isInterClusterRequest(TransportRequest request, X509Certificate[] certs) {
            // TODO Auto-generated method stub
            return false;
        }
        
    }
}
