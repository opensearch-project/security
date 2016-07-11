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
import org.elasticsearch.index.IndexModule.IndexSearcherWrapperFactory;
import org.elasticsearch.index.IndexService;
import org.elasticsearch.index.shard.IndexSearcherWrapper;

public class SearchGuardIndexSearcherWrapperFactory implements IndexSearcherWrapperFactory {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private static volatile IndexSearcherWrapper searchGuardFlsDlsIndexSearcherWrapper = null;

    
    /*
    @Override
    protected void configure() {
        //TODO how often called?
        final Multibinder wrapperMultibinder = Multibinder.newSetBinder(binder(), IndexSearcherWrapper.class);

        if(searchGuardFlsDlsIndexSearcherWrapper != null) {
            wrapperMultibinder.addBinding().to(searchGuardFlsDlsIndexSearcherWrapper);
            return;
        }
        
        try {
            Class _searchGuardFlsDlsIndexSearcherWrapper;
            if ((_searchGuardFlsDlsIndexSearcherWrapper = Class
                    .forName("com.floragunn.searchguard.configuration.SearchGuardFlsDlsIndexSearcherWrapper")) != null) {
                wrapperMultibinder.addBinding().to(_searchGuardFlsDlsIndexSearcherWrapper);
                searchGuardFlsDlsIndexSearcherWrapper = _searchGuardFlsDlsIndexSearcherWrapper;
                log.info("FLS/DLS enabled");
            } else {
                throw new ClassNotFoundException();
            }

        } catch (final ClassNotFoundException e) {
            log.debug("FLS/DLS not enabled");
            wrapperMultibinder.addBinding().to(SearchGuardIndexSearcherWrapper.class);
        }

    }
*/


    @Override
    public IndexSearcherWrapper newWrapper(IndexService indexService) {
        /*if(searchGuardFlsDlsIndexSearcherWrapper != null) {
            return searchGuardFlsDlsIndexSearcherWrapper;
        }
        
        try {
            Class _searchGuardFlsDlsIndexSearcherWrapper;
            if ((_searchGuardFlsDlsIndexSearcherWrapper = Class
                    .forName("com.floragunn.searchguard.configuration.SearchGuardFlsDlsIndexSearcherWrapper")) != null) {
                
                wrapperMultibinder.addBinding().to(_searchGuardFlsDlsIndexSearcherWrapper);
                searchGuardFlsDlsIndexSearcherWrapper = _searchGuardFlsDlsIndexSearcherWrapper;
                log.info("FLS/DLS enabled");
            } else {
                throw new ClassNotFoundException();
            }

        } catch (final ClassNotFoundException e) {
            log.debug("FLS/DLS not enabled");
            wrapperMultibinder.addBinding().to(SearchGuardIndexSearcherWrapper.class);
        }*/
        
        return null;
        
    }

}
