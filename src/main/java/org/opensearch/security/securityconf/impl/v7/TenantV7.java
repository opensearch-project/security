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
 * Copyright OpenSearch Contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package org.opensearch.security.securityconf.impl.v7;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.opensearch.security.securityconf.Hideable;
import org.opensearch.security.securityconf.StaticDefinable;

public class TenantV7 implements Hideable, StaticDefinable {

    private boolean reserved;
    private boolean hidden;
    @JsonProperty(value = "static")
    private boolean _static;
    private String description;
    
    public boolean isHidden() {
        return hidden;
    }
    public void setHidden(boolean hidden) {
        this.hidden = hidden;
    }
    public String getDescription() {
        return description;
    }
    public void setDescription(String description) {
        this.description = description;
    }
    public boolean isReserved() {
        return reserved;
    }
    public void setReserved(boolean reserved) {
        this.reserved = reserved;
    }
    
    
    @JsonProperty(value = "static")
    public boolean isStatic() {
        return _static;
    }
    @JsonProperty(value = "static")
    public void setStatic(boolean _static) {
        this._static = _static;
    }
    @Override
    public String toString() {
        return "TenantV7 [reserved=" + reserved + ", hidden=" + hidden + ", _static=" + _static + ", description=" + description + "]";
    }
    
    
}