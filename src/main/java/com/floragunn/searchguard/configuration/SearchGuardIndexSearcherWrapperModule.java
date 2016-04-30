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

package com.floragunn.searchguard.configuration;

import org.elasticsearch.common.inject.AbstractModule;
import org.elasticsearch.common.inject.multibindings.Multibinder;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.index.engine.IndexSearcherWrapper;

public class SearchGuardIndexSearcherWrapperModule extends AbstractModule{

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    
    @Override
    protected void configure() {
        Multibinder multibinder = Multibinder.newSetBinder(binder(), IndexSearcherWrapper.class);
        
        try {
            Class searchGuardFlsDlsIndexSearcherWrapper;
            if((searchGuardFlsDlsIndexSearcherWrapper = Class.forName("com.floragunn.searchguard.configuration.SearchGuardFlsDlsIndexSearcherWrapper")) != null)
            {
                multibinder.addBinding().to(searchGuardFlsDlsIndexSearcherWrapper);
                log.info("FLS/DLS enabled");
            }
        } catch (ClassNotFoundException e) {
            log.debug("FLS/DLS not enabled");
            multibinder.addBinding().to(SearchGuardIndexSearcherWrapper.class);
        }
        
    }

}
