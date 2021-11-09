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

package org.opensearch.security.auditlog.impl;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.InetSocketAddress;

import org.opensearch.security.auditlog.AuditTestUtils;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.transport.TransportAddress;
import org.opensearch.security.auditlog.integration.TestAuditlogImpl;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Created by martin.stange on 19.04.2017.
 */
public class IgnoreAuditUsersTest {

    ClusterService cs = mock(ClusterService.class);
    DiscoveryNode dn = mock(DiscoveryNode.class);

    @Before
    public void setup() {
        when(dn.getHostAddress()).thenReturn("hostaddress");
        when(dn.getId()).thenReturn("hostaddress");
        when(dn.getHostName()).thenReturn("hostaddress");
        when(cs.localNode()).thenReturn(dn);
        when(cs.getClusterName()).thenReturn(new ClusterName("cname"));
    }

    static String ignoreUser = "Wesley Crusher";
    String nonIgnoreUser = "Diana Crusher";
    private final User ignoreUserObj = new User(ignoreUser);
    static SearchRequest sr;

    @BeforeClass
    public static void initSearchRequest() {
        sr = new SearchRequest();
        sr.indices("index1", "logstash*");
        sr.types("mytype", "logs");
    }



    @Test
    public void testConfiguredIgnoreUser() {

        Settings settings = Settings.builder()
                .put("opendistro_security.audit.ignore_users", ignoreUser)
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .build();
        AbstractAuditLog al = AuditTestUtils.createAuditLog(settings, null, null, newThreadPool(ConfigConstants.OPENDISTRO_SECURITY_USER, ignoreUserObj), null, cs);
        TestAuditlogImpl.clear();
        al.logGrantedPrivileges("indices:data/read/search", sr, null);
        Assert.assertEquals(0, TestAuditlogImpl.messages.size());
    }

    @Test
    public void testNonConfiguredIgnoreUser() {
        Settings settings = Settings.builder()
                .put("opendistro_security.audit.ignore_users", nonIgnoreUser)
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
                .build();
        AbstractAuditLog al = AuditTestUtils.createAuditLog(settings, null, null, newThreadPool(ConfigConstants.OPENDISTRO_SECURITY_USER, ignoreUserObj), null, cs);
        TestAuditlogImpl.clear();
        al.logGrantedPrivileges("indices:data/read/search", sr, null);
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
    }

    @Test
    public void testNonExistingIgnoreUser() {
        Settings settings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
                .build();
        AbstractAuditLog al = AuditTestUtils.createAuditLog(settings, null, null, newThreadPool(ConfigConstants.OPENDISTRO_SECURITY_USER, ignoreUserObj), null, cs);
        TestAuditlogImpl.clear();
        al.logGrantedPrivileges("indices:data/read/search", sr, null);
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
    }

    @Test
    public void testWildcards() {

        SearchRequest sr = new SearchRequest();
        User user = new User("John Doe");
        //sr.putInContext(ConfigConstants.OPENDISTRO_SECURITY_USER, user);
        //sr.putInContext(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, "8.8.8.8");
        //sr.putInContext(ConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PRINCIPAL, "CN=kirk,OU=client,O=client,L=test,C=DE");
        //sr.putHeader("myheader", "hval");
        sr.indices("index1","logstash*");
        sr.types("mytype","logs");
        //sr.source("{\"query\": false}");

        Settings settings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true)
                .putList("opendistro_security.audit.ignore_users", "*")
                .build();

        TransportAddress ta = new TransportAddress(new InetSocketAddress("8.8.8.8",80));

        AbstractAuditLog al = AuditTestUtils.createAuditLog(settings, null, null, newThreadPool(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, ta,
                                                                             ConfigConstants.OPENDISTRO_SECURITY_USER, new User("John Doe"),
                                                                             ConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PRINCIPAL, "CN=kirk,OU=client,O=client,L=test,C=DE"
                                                                              ), null, cs);
        TestAuditlogImpl.clear();
        al.logGrantedPrivileges("indices:data/read/search", sr, null);
        Assert.assertEquals(0, TestAuditlogImpl.messages.size());

        settings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
                .putList("opendistro_security.audit.ignore_users", "xxx")
                .build();
        al = AuditTestUtils.createAuditLog(settings, null, null, newThreadPool(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, ta,
                ConfigConstants.OPENDISTRO_SECURITY_USER, new User("John Doe"),
                ConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PRINCIPAL, "CN=kirk,OU=client,O=client,L=test,C=DE"
                 ), null, cs);
        TestAuditlogImpl.clear();
        al.logGrantedPrivileges("indices:data/read/search", sr, null);
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());

        settings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
                .putList("opendistro_security.audit.ignore_users", "John Doe","Capatin Kirk")
                .build();
        al = AuditTestUtils.createAuditLog(settings, null, null, newThreadPool(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, ta,
                ConfigConstants.OPENDISTRO_SECURITY_USER, new User("John Doe"),
                ConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PRINCIPAL, "CN=kirk,OU=client,O=client,L=test,C=DE"
                 ), null, cs);
        TestAuditlogImpl.clear();
        al.logGrantedPrivileges("indices:data/read/search", sr, null);
        al.logSecurityIndexAttempt(sr, "indices:data/read/search", null);
        al.logMissingPrivileges("indices:data/read/search",sr, null);
        Assert.assertEquals(TestAuditlogImpl.messages.toString(), 0, TestAuditlogImpl.messages.size());

        settings = Settings.builder()
                .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "NONE")
                .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "NONE")
                .putList("opendistro_security.audit.ignore_users", "Wil Riker","Capatin Kirk")
                .build();
        al = AuditTestUtils.createAuditLog(settings, null, null, newThreadPool(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, ta,
                ConfigConstants.OPENDISTRO_SECURITY_USER, new User("John Doe"),
                ConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PRINCIPAL, "CN=kirk,OU=client,O=client,L=test,C=DE"
                 ), null, cs);
        TestAuditlogImpl.clear();
        al.logGrantedPrivileges("indices:data/read/search", sr, null);
        Assert.assertEquals(1, TestAuditlogImpl.messages.size());
    }

    private static ThreadPool newThreadPool(Object... transients) {
        ThreadPool tp = new ThreadPool(Settings.builder().put("node.name",  "mock").build());
        for(int i=0;i<transients.length;i=i+2)
            tp.getThreadContext().putTransient((String)transients[i], transients[i+1]);
        return tp;
    }
}
