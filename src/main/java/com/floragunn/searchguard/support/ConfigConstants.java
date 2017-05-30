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

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class ConfigConstants {
    
     
    public static final String SG_CONFIG_PREFIX = "_sg_";
    
    public static final String SG_CHANNEL_TYPE = SG_CONFIG_PREFIX+"channel_type";
    
    public static final String SG_DLS_QUERY = SG_CONFIG_PREFIX+"dls_query";
    public static final String SG_FLS_FIELDS = SG_CONFIG_PREFIX+"fls_fields";
    
    //public static final String SG_INTERNAL_REQUEST = SG_CONFIG_PREFIX+"internal_request";
    
    public static final String SG_CONF_REQUEST_HEADER = SG_CONFIG_PREFIX+"conf_request";
    
    public static final String SG_REMOTE_ADDRESS = SG_CONFIG_PREFIX+"remote_address";
    public static final String SG_REMOTE_ADDRESS_HEADER = SG_CONFIG_PREFIX+"remote_address_header";
    
    //public static final String SG_SGROLES = SG_CONFIG_PREFIX+"sgroles";
    
    /**
     * Set by SSL plugin for https requests only
     */
    public static final String SG_SSL_PEER_CERTIFICATES = SG_CONFIG_PREFIX+"ssl_peer_certificates";
    
    /**
     * Set by SSL plugin for https requests only
     */
    public static final String SG_SSL_PRINCIPAL = SG_CONFIG_PREFIX+"ssl_principal";
    
    /**
     * If this is set to TRUE then the request comes from a Server Node (fully trust)
     * Its expected that there is a _sg_user attached as header
     */
    public static final String SG_SSL_TRANSPORT_INTERCLUSTER_REQUEST = SG_CONFIG_PREFIX+"ssl_transport_intercluster_request";
    
    /**
     * Set by the SSL plugin, this is the peer node certificate on the transport layer
     */
    public static final String SG_SSL_TRANSPORT_PRINCIPAL = SG_CONFIG_PREFIX+"ssl_transport_principal";
    
    public static final String SG_USER = SG_CONFIG_PREFIX+"user";
    public static final String SG_USER_HEADER = SG_CONFIG_PREFIX+"user_header";
    
    public static final String SG_XFF_DONE = SG_CONFIG_PREFIX+"xff_done";

    public static final String SG_CONFIG_INDEX = "searchguard.config_index_name";
    public static final String SG_DEFAULT_CONFIG_INDEX = "searchguard";

    public static final String SG_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE = "searchguard.enable_snapshot_restore_privilege";
    public static final boolean SG_DEFAULT_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE = false;

    public static final String SG_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES = "searchguard.check_snapshot_restore_write_privileges";
    public static final boolean SG_DEFAULT_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES = true;
    public static final Set<String> SG_SNAPSHOT_RESTORE_NEEDED_WRITE_PRIVILEGES = Collections.unmodifiableSet(
            new HashSet<String>(Arrays.asList(
                    "indices:admin/create",
                    "indices:data/write/index"
                    // "indices:data/write/bulk"
              )));

    public final static String CONFIGNAME_ROLES = "roles";
    public final static String CONFIGNAME_ROLES_MAPPING = "rolesmapping";
    public final static String CONFIGNAME_ACTION_GROUPS = "actiongroups";
    public final static String CONFIGNAME_INTERNAL_USERS = "internalusers";
    public final static String CONFIGNAME_CONFIG = "config";
    
    //TODO public static arrays are unsafe. Check callers and change to an unmodifiable Set
    @Deprecated
    public final static String[] CONFIGNAMES = new String[] {CONFIGNAME_ROLES, CONFIGNAME_ROLES_MAPPING, 
            CONFIGNAME_ACTION_GROUPS, CONFIGNAME_INTERNAL_USERS, CONFIGNAME_CONFIG};
    public static final String SG_INTERCLUSTER_REQUEST_EVALUATOR_CLASS = "searchguard.cert.intercluster_request_evaluator_class";

}
