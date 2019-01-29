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

package org.elasticsearch.node;

import java.util.Arrays;
import java.util.Random;

import org.elasticsearch.common.logging.LogConfigurator;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.plugins.Plugin;

public class PluginAwareNode extends Node {
    
    private final boolean masterEligible;

    @SafeVarargs
    public PluginAwareNode(boolean masterEligible, final Settings preparedSettings, final Class<? extends Plugin>... plugins) {
        super(InternalSettingsPreparer.prepareEnvironment(checkAndAddNodeName(preparedSettings), null), Arrays.asList(plugins), true);
        this.masterEligible = masterEligible;
    }
    
    @Override
    protected void registerDerivedNodeNameWithLogger(String nodeName) {
        LogConfigurator.setNodeName(nodeName);
    }

    public boolean isMasterEligible() {
        return masterEligible;
    }
    
    private static Settings checkAndAddNodeName(final Settings settings) {
    	if(!settings.hasValue("node.name")) {
    		return Settings.builder().put(settings).put("node.name", "auto_node_name_"+System.currentTimeMillis()+"_"+ new Random().nextInt()).build();
    	}
    	
    	return settings;
    	
    }
}
