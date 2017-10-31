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

package com.floragunn.searchguard.auditlog;

import java.io.Closeable;

import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.transport.TransportRequest;

public interface AuditLog extends Closeable {

    //login
    void logFailedLogin(String effectiveUser, boolean sgadmin, String initiatingUser, TransportRequest request, Task task);
    void logFailedLogin(String effectiveUser, boolean sgadmin, String initiatingUser, RestRequest request);
    void logSucceededLogin(String effectiveUser, boolean sgadmin, String initiatingUser, TransportRequest request, Task task);
    void logSucceededLogin(String effectiveUser, boolean sgadmin, String initiatingUser, RestRequest request);

    //privs
    void logMissingPrivileges(String privilege, String initiatingUser, RestRequest request);
    void logMissingPrivileges(String privilege, TransportRequest request, Task task);
    void logGrantedPrivileges(String privilege, TransportRequest request, Task task);

    //spoof
    void logBadHeaders(TransportRequest request, String action, Task task);
    void logBadHeaders(RestRequest request);

    void logSgIndexAttempt(TransportRequest request, String action, Task task);
    
    void logSSLException(TransportRequest request, Throwable t, String action, Task task);
    void logSSLException(RestRequest request, Throwable t);
    
    public enum Origin {
        REST, TRANSPORT, LOCAL
    }
}
