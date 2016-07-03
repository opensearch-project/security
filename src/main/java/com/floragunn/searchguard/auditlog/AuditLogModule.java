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

package com.floragunn.searchguard.auditlog;

import org.elasticsearch.common.inject.AbstractModule;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;

public class AuditLogModule extends AbstractModule {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    
    @Override
    protected void configure() {
        try {
            Class auditLogImpl;
            if ((auditLogImpl = Class
                    .forName("com.floragunn.searchguard.auditlog.impl.AuditLogImpl")) != null) {
                bind(AuditLog.class).to(auditLogImpl).asEagerSingleton();
                log.info("Auditlog available ({})", auditLogImpl.getSimpleName());
            } else {
                throw new ClassNotFoundException();
            }
        } catch (ClassNotFoundException e) {
            bind(AuditLog.class).to(NullAuditLog.class).asEagerSingleton();
            log.info("Auditlog not available");
        }
        
       
    }
}
