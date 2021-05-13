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
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import java.util.Collections;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.opensearch.security.securityconf.Hideable;
import org.opensearch.security.securityconf.StaticDefinable;
import org.opensearch.security.securityconf.impl.v6.ActionGroupsV6;

public class ActionGroupsV7 implements Hideable, StaticDefinable {

    
    
    private boolean reserved;
    private boolean hidden;
    @JsonProperty(value = "static")
    private boolean _static;
    private List<String> allowed_actions = Collections.emptyList();
    private String type;
    private String description;
    
    public ActionGroupsV7() {
        super();
    }
    public ActionGroupsV7(String agName, ActionGroupsV6 ag6) {
        reserved = ag6.isReserved();
        hidden = ag6.isHidden();
        allowed_actions = ag6.getPermissions();
        type = agName.toLowerCase().contains("cluster")?"cluster":"index";
        description = "Migrated from v6";
    }

    public ActionGroupsV7(String key, List<String> allowed_actions) {
        this.allowed_actions = allowed_actions;
        type = "unknown";
        description = "Migrated from v6 (legacy)";
    }
    public String getType() {
        return type;
    }
    public void setType(String type) {
        this.type = type;
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
    public boolean isHidden() {
        return hidden;
    }
    public void setHidden(boolean hidden) {
        this.hidden = hidden;
    }
    public List<String> getAllowed_actions() {
        return allowed_actions;
    }
    public void setAllowed_actions(List<String> allowed_actions) {
        this.allowed_actions = allowed_actions;
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
        return "ActionGroupsV7 [reserved=" + reserved + ", hidden=" + hidden + ", _static=" + _static + ", allowed_actions=" + allowed_actions
                + ", type=" + type + ", description=" + description + "]";
    }
    
    
    
    
}