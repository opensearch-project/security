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

package com.amazon.opendistroforelasticsearch.security.configuration;


import java.util.Collection;
import java.util.Map;

import org.elasticsearch.common.settings.Settings;

/**
 * Abstraction layer over Open Distro Security configuration repository
 */
public interface ConfigurationRepository {

    /**
     * Load configuration from persistence layer
     *
     * @param configurationType not null configuration identifier
     * @return configuration found by specified type in persistence layer or {@code null} if persistence layer
     * doesn't have configuration by requested type, or persistence layer not ready yet
     * @throws NullPointerException if specified configuration type is null or empty
     */
    
    Settings getConfiguration(String configurationType);

    /**
     * Bulk load configuration from persistence layer
     *
     * @param configTypes not null collection with not null configuration identifiers by that need load configurations
     * @return not null map where key it configuration type for found configuration and value it not null {@link Settings}
     * that represent configuration for correspond type. If by requested type configuration absent in persistence layer,
     * they will be absent in result map
     * @throws NullPointerException if specified collection with type null or contain null or empty types
     */
    //Map<String, Settings> getConfiguration(Collection<String> configTypes);

    /**
     * Bulk reload configuration from persistence layer. If configuration was modify manually bypassing business logic define
     * in {@link ConfigurationRepository}, this method should catch up it logic. This method can be very slow, because it skip
     * all caching logic and should be use only as a last resort.
     *
     * @param configTypes not null collection with not null configuration identifiers by that need load configurations
     * @return not null map where key it configuration type for found configuration and value it not null {@link Settings}
     * that represent configuration for correspond type. If by requested type configuration absent in persistence layer,
     * they will be absent in result map
     * @throws NullPointerException if specified collection with type null or contain null or empty types
     */
    Map<String, Settings> reloadConfiguration(Collection<String> configTypes);

    /**
     * Save changed configuration in persistence layer. After save, changes will be available for
     * read via {@link ConfigurationRepository#getConfiguration(String)}
     *
     * @param configurationType not null configuration identifier
     * @param settings          not null configuration that need persist
     * @throws NullPointerException if specified configuration is null or configuration type is null or empty
     */
    void persistConfiguration(String configurationType, Settings settings);

    /**
     * Subscribe on configuration change
     *
     * @param configurationType not null and not empty configuration type of which changes need notify listener
     * @param listener          not null callback function that will be execute when specified type will modify
     * @throws NullPointerException if specified configuration type is null or empty, or callback function is null
     */
    void subscribeOnChange(String configurationType, ConfigurationChangeListener listener);
}
