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

import java.io.Closeable;

import org.elasticsearch.client.Client;
import org.elasticsearch.common.component.AbstractLifecycleComponent;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;

/**
 * 
 * This class only exist to initialize guice correctly
 *
 */

public class ConfigurationService extends AbstractLifecycleComponent<ConfigurationService> implements Closeable {
	
	public final static String CONFIGNAME_ROLES = "roles";
	public final static String CONFIGNAME_ROLES_MAPPING = "rolesmapping";
	public final static String CONFIGNAME_ACTION_GROUPS = "actiongroups";
	public final static String CONFIGNAME_INTERNAL_USERS = "internalusers";
	public final static String CONFIGNAME_CONFIG = "config";
	public final static String[] CONFIGNAMES = new String[] {CONFIGNAME_ROLES, CONFIGNAME_ROLES_MAPPING, 
			CONFIGNAME_ACTION_GROUPS, CONFIGNAME_INTERNAL_USERS, CONFIGNAME_CONFIG};
	
    @Inject
    public ConfigurationService(final Settings settings, final Client client) {
        super(settings);
    }

    @Override
    protected void doStart() {
     // do nothing
    }

    @Override
    protected void doStop() {
     // do nothing
    }

    @Override
    protected void doClose() {
     // do nothing
    }   
}
