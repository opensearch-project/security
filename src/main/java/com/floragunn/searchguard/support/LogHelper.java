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

package com.floragunn.searchguard.support;

import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.util.concurrent.ThreadContext;

public class LogHelper {

    private static final ESLogger USER_TRACE_LOGGER = Loggers.getLogger("com.floragunn.searchguard.usertracelogger");
    
    public static void logUserTrace(String msg, Object... params) {
        if(USER_TRACE_LOGGER.isTraceEnabled()) {
            
            String tn = Thread.currentThread().getName();
            
            if(tn.startsWith("elasticsearch[")) {
                tn = tn.substring(14, tn.indexOf("]", 15));
            }
            
            USER_TRACE_LOGGER.trace(tn+"::"+msg, params);
        }
    }
    
    public static String toString(final ThreadContext context) {
        
    	final StringBuilder sb = new StringBuilder();
        sb.append("Headers:" + System.lineSeparator());
        for (final String key : context.getHeaders().keySet()) {
            sb.append(key + "=" + context.getHeaders().get(key) + System.lineSeparator());
        }
        // TODO 5.0: can't access transient headers directly
//        sb.append("Context:" + System.lineSeparator());
//        for (final Object key : context.getTransientHeaders().keySet()) {
//            sb.append(key + "=" + holder.getFromContext(key) + System.lineSeparator());
//        }
        return sb.toString();
    }

}
