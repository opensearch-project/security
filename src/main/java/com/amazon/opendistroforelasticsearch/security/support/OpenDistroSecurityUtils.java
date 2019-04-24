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

package com.amazon.opendistroforelasticsearch.security.support;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class OpenDistroSecurityUtils {
    
    protected final static Logger log = LogManager.getLogger(OpenDistroSecurityUtils.class);
    public static Locale EN_Locale = forEN();


    private OpenDistroSecurityUtils() {
    }

    //https://github.com/tonywasher/bc-java/commit/ee160e16aa7fc71330907067c5470e9bf3e6c383
    //The Legion of the Bouncy Castle Inc
    private static Locale forEN()
    {
        if ("en".equalsIgnoreCase(Locale.getDefault().getLanguage()))
        {
            return Locale.getDefault();
        }

        Locale[] locales = Locale.getAvailableLocales();
        for (int i = 0; i != locales.length; i++)
        {
            if ("en".equalsIgnoreCase(locales[i].getLanguage()))
            {
                return locales[i];
            }
        }

        return Locale.getDefault();
    }

    public static String evalMap(final Map<String,Set<String>> map, final String index) {

        if (map == null) {
            return null;
        }

        if (map.get(index) != null) {
            return index;
        } else if (map.get("*") != null) {
            return "*";
        }
        if (map.get("_all") != null) {
            return "_all";
        }

        //regex
        for(final String key: map.keySet()) {
            if(WildcardMatcher.containsWildcard(key)
                    && WildcardMatcher.match(key, index)) {
                return key;
            }
        }

        return null;
    }
    
    @SafeVarargs
    public static <T> Map<T, T>  mapFromArray(T ... keyValues) {
        if(keyValues == null) {
            return Collections.emptyMap();
        }
        if (keyValues.length % 2 != 0) {
            log.error("Expected even number of key/value pairs, got {}.", Arrays.toString(keyValues));
            return null;
        }
        Map<T, T> map = new HashMap<>();
        
        for(int i = 0; i<keyValues.length; i+=2) {
            map.put(keyValues[i], keyValues[i+1]);
        }
        return map;
    }
}
