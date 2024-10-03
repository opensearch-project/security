/*
 * Copyright 2015-2017 floragunn GmbH
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
/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.securityconf.impl;

import com.fasterxml.jackson.annotation.JsonIgnore;

public class Meta {

    private String type;
    private int config_version;

    private CType<?> cType;

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
        cType = CType.fromString(type);
    }

    public int getConfig_version() {
        return config_version;
    }

    public void setConfig_version(int config_version) {
        this.config_version = config_version;
    }

    @JsonIgnore
    public CType<?> getCType() {
        return cType;
    }

    @Override
    public String toString() {
        return "Meta [type=" + type + ", config_version=" + config_version + ", cType=" + cType + "]";
    }

}
