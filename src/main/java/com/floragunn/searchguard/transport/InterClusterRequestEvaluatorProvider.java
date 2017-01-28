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

import java.lang.reflect.Constructor;

import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.inject.Provider;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;

public class InterClusterRequestEvaluatorProvider implements Provider<InterClusterRequestEvaluator> {

    static final String KEY = "searchguard.cert.intercluster_request_evaluator";
    private final ESLogger log = Loggers.getLogger(this.getClass());
    private InterClusterRequestEvaluator evaluator;
    
    @Inject
    public InterClusterRequestEvaluatorProvider(final Settings settings) {
        final String className = settings.get(KEY, DefaultInterClusterRequestEvaluator.class.getName());
        log.info("Using {} ", className);
        if(!className.equals(DefaultInterClusterRequestEvaluator.class.getName())) {
            try {
                Class<?> klass = Class.forName(className);
                Constructor<?> constructor = klass.getConstructor(Settings.class);
                evaluator =  (InterClusterRequestEvaluator) constructor.newInstance(settings);
                return;
            }catch(Exception e) {
                log.warn("Using DefaultInterClusterRequestEvaluator. Unable to instantiate {} ", e, className);
                if(log.isTraceEnabled()) {
                    log.trace("Unable to instantiate InterClusterRequestEvaluator", e);
                }
            }
        }
        evaluator = new DefaultInterClusterRequestEvaluator(settings);
    }
    
    @Override
    public InterClusterRequestEvaluator get() {
        return evaluator;
    }
    
}
