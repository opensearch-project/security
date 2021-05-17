/*
 * Copyright 2017 floragunn GmbH
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

package org.opensearch.security.ssl.util;


public class Utils {
    public static <T> T coalesce(T first, T... more) {
        if (first != null) {
            return first;
        }
        
        if(more == null || more.length == 0) {
            return null;
        }
        
        for (int i = 0; i < more.length; i++) {
            T t = more[i];
            if(t != null) {
                return t;
            }
        }
        
        return null;
      }

    public static char[] toCharArray(String str) {
        return (str == null || str.length() == 0) ? null : str.toCharArray();
    }
}
