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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.inject.Provider;
import org.elasticsearch.common.settings.Settings;

import com.floragunn.searchguard.support.ConfigConstants;

public final class InterClusterRequestEvaluatorProvider implements Provider<InterClusterRequestEvaluator> {

    private static final String DEFAULT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS = DefaultInterClusterRequestEvaluator.class.getName();
    private final Logger log = LogManager.getLogger(this.getClass());
    private InterClusterRequestEvaluator evaluator;

    @Inject
    public InterClusterRequestEvaluatorProvider(final Settings settings) {
        final String className = settings.get(ConfigConstants.SG_INTERCLUSTER_REQUEST_EVALUATOR_CLASS,
                DEFAULT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS);
        log.debug("Using {} as intercluster request evaluator class", className);
        if (!DEFAULT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS.equals(className)) {
            try {
                final Class<?> klass = Class.forName(className);
                final Constructor<?> constructor = klass.getConstructor(Settings.class);
                evaluator = (InterClusterRequestEvaluator) constructor.newInstance(settings);
                return;
            } catch (Throwable e) {
                log.error("Using DefaultInterClusterRequestEvaluator. Unable to instantiate {} ", e, className);
                if (log.isTraceEnabled()) {
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
