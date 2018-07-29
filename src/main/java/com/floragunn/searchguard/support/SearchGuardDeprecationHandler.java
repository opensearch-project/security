/*
 * Copyright 2015-2018 floragunn GmbH
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

package com.floragunn.searchguard.support;

import org.elasticsearch.common.xcontent.DeprecationHandler;

public class SearchGuardDeprecationHandler {
    
    public final static DeprecationHandler INSTANCE = new DeprecationHandler() {
        @Override
        public void usedDeprecatedField(String usedName, String replacedWith) {
            throw new UnsupportedOperationException("deprecated fields not supported here but got ["
                + usedName + "] which is a deprecated name for [" + replacedWith + "]");
        }
        @Override
        public void usedDeprecatedName(String usedName, String modernName) {
            throw new UnsupportedOperationException("deprecated fields not supported here but got ["
                + usedName + "] which has been replaced with [" + modernName + "]");
        }
    };

}
