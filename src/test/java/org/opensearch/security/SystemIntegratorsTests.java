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

package org.opensearch.security;

import org.apache.http.HttpStatus;
import org.apache.http.message.BasicHeader;
import org.opensearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.cluster.ClusterConfiguration;
import org.opensearch.security.test.helper.rest.RestHelper;
import com.google.common.collect.Lists;

public class SystemIntegratorsTests extends SingleClusterTest {
    
    @Test
    public void testInjectedUserMalformed() throws Exception {
    
        final Settings settings = Settings.builder()                
                .put(ConfigConstants.SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, true)
                .put("http.type", "org.opensearch.security.http.UserInjectingServerTransport")
                .build();
                      
        setup(settings, ClusterConfiguration.USERINJECTOR);
        
        final RestHelper rh = nonSslRestHelper();
        // username|role1,role2|remoteIP|attributes
        
        HttpResponse resc;
        
        resc = rh.executeGetRequest("_opendistro/_security/authinfo", new BasicHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, null));
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, resc.getStatusCode());

        resc = rh.executeGetRequest("_opendistro/_security/authinfo", new BasicHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "|||"));
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, resc.getStatusCode());
        
        resc = rh.executeGetRequest("_opendistro/_security/authinfo", new BasicHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "||127.0.0:80|"));
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, resc.getStatusCode());
        
        resc = rh.executeGetRequest("_opendistro/_security/authinfo", new BasicHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "username||ip|"));
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, resc.getStatusCode());

        resc = rh.executeGetRequest("_opendistro/_security/authinfo", new BasicHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "username||ip:port|"));
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, resc.getStatusCode());

        resc = rh.executeGetRequest("_opendistro/_security/authinfo", new BasicHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "username||ip:80|"));
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, resc.getStatusCode());

        resc = rh.executeGetRequest("_opendistro/_security/authinfo", new BasicHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "username||127.0.x:80|"));
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, resc.getStatusCode());

        resc = rh.executeGetRequest("_opendistro/_security/authinfo", new BasicHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "username||127.0.0:80|key1,value1,key2"));
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, resc.getStatusCode());

        resc = rh.executeGetRequest("_opendistro/_security/authinfo", new BasicHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "||127.0.0:80|key1,value1,key2,value2"));
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, resc.getStatusCode());
        
    }

    @Test
    public void testInjectedUser() throws Exception {
    
        final Settings settings = Settings.builder()                
                .put(ConfigConstants.SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, true)
                .put("http.type", "org.opensearch.security.http.UserInjectingServerTransport")
                .build();
                      
        setup(settings, ClusterConfiguration.USERINJECTOR);
        
        final RestHelper rh = nonSslRestHelper();
        // username|role1,role2|remoteIP|attributes
        
        HttpResponse resc;
               
        resc = rh.executeGetRequest("_opendistro/_security/authinfo", new BasicHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "admin||127.0.0:80|"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("User [name=admin, backend_roles=[], requestedTenant=null]"));
        Assert.assertTrue(resc.getBody().contains("\"remote_address\":\"127.0.0.0:80\""));
        Assert.assertTrue(resc.getBody().contains("\"backend_roles\":[]"));
        Assert.assertTrue(resc.getBody().contains("\"custom_attribute_names\":[]"));

        resc = rh.executeGetRequest("_opendistro/_security/authinfo", new BasicHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "admin|role1|127.0.0:80|key1,value1"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("User [name=admin, backend_roles=[role1], requestedTenant=null]"));
        Assert.assertTrue(resc.getBody().contains("\"remote_address\":\"127.0.0.0:80\""));
        Assert.assertTrue(resc.getBody().contains("\"backend_roles\":[\"role1\"]"));
        Assert.assertTrue(resc.getBody().contains("\"custom_attribute_names\":[\"key1\"]"));

        resc = rh.executeGetRequest("_opendistro/_security/authinfo", new BasicHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "admin|role1,role2||key1,value1"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("User [name=admin, backend_roles=[role1, role2], requestedTenant=null]"));
        // remote IP is assigned by XFFResolver
        Assert.assertFalse(resc.getBody().contains("\"remote_address\":null"));
        Assert.assertTrue(resc.getBody().contains("\"backend_roles\":[\"role1\",\"role2\"]"));
        Assert.assertTrue(resc.getBody().contains("\"custom_attribute_names\":[\"key1\"]"));

        resc = rh.executeGetRequest("_opendistro/_security/authinfo", new BasicHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "admin|role1,role2|8.8.8.8:8|key1,value1,key2,value2"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("User [name=admin, backend_roles=[role1, role2], requestedTenant=null]"));
        // remote IP is assigned by XFFResolver
        Assert.assertFalse(resc.getBody().contains("\"remote_address\":null"));
        Assert.assertTrue(resc.getBody().contains("\"backend_roles\":[\"role1\",\"role2\"]"));
        Assert.assertTrue(resc.getBody().contains("\"custom_attribute_names\":[\"key1\",\"key2\"]"));

        resc = rh.executeGetRequest("_opendistro/_security/authinfo", new BasicHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "nagilum|role1,role2|8.8.8.8:8|key1,value1,key2,value2"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("User [name=nagilum, backend_roles=[role1, role2], requestedTenant=null]"));
        // remote IP is assigned by XFFResolver
        Assert.assertTrue(resc.getBody().contains("\"remote_address\":\"8.8.8.8:8\""));
        Assert.assertTrue(resc.getBody().contains("\"backend_roles\":[\"role1\",\"role2\"]"));
        // mapped by username
        Assert.assertTrue(resc.getBody().contains("\"roles\":[\"opendistro_security_all_access\""));
        Assert.assertTrue(resc.getBody().contains("\"custom_attribute_names\":[\"key1\",\"key2\"]"));
        
        resc = rh.executeGetRequest("_opendistro/_security/authinfo", new BasicHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "myuser|role1,vulcanadmin|8.8.8.8:8|key1,value1,key2,value2"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("User [name=myuser, backend_roles=[role1, vulcanadmin], requestedTenant=null]"));
        // remote IP is assigned by XFFResolver
        Assert.assertTrue(resc.getBody().contains("\"remote_address\":\"8.8.8.8:8\""));
        Assert.assertTrue(resc.getBody().contains("\"backend_roles\":[\"role1\",\"vulcanadmin\"]"));
        // mapped by backend role "twitter"
        Assert.assertTrue(resc.getBody().contains("\"roles\":[\"public\",\"role_vulcans_admin\"]"));
        Assert.assertTrue(resc.getBody().contains("\"custom_attribute_names\":[\"key1\",\"key2\"]"));
        
        // add requested tenant
        resc = rh.executeGetRequest("_opendistro/_security/authinfo", new BasicHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "myuser|role1,vulcanadmin|8.8.8.8:8|key1,value1,key2,value2|"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("User [name=myuser, backend_roles=[role1, vulcanadmin], requestedTenant=null]"));
        // remote IP is assigned by XFFResolver
        Assert.assertTrue(resc.getBody().contains("\"remote_address\":\"8.8.8.8:8\""));
        Assert.assertTrue(resc.getBody().contains("\"backend_roles\":[\"role1\",\"vulcanadmin\"]"));
        // mapped by backend role "twitter"
        Assert.assertTrue(resc.getBody(), resc.getBody().contains("\"roles\":[\"public\",\"role_vulcans_admin\"]"));
        Assert.assertTrue(resc.getBody().contains("\"custom_attribute_names\":[\"key1\",\"key2\"]"));

        resc = rh.executeGetRequest("_opendistro/_security/authinfo", new BasicHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "myuser|role1,vulcanadmin|8.8.8.8:8|key1,value1,key2,value2|mytenant"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("User [name=myuser, backend_roles=[role1, vulcanadmin], requestedTenant=mytenant]"));
        // remote IP is assigned by XFFResolver
        Assert.assertTrue(resc.getBody().contains("\"remote_address\":\"8.8.8.8:8\""));
        Assert.assertTrue(resc.getBody().contains("\"backend_roles\":[\"role1\",\"vulcanadmin\"]"));
        // mapped by backend role "twitter"
        Assert.assertTrue(resc.getBody().contains("\"roles\":[\"public\",\"role_vulcans_admin\"]"));
        Assert.assertTrue(resc.getBody().contains("\"custom_attribute_names\":[\"key1\",\"key2\"]"));

        resc = rh.executeGetRequest("_opendistro/_security/authinfo", new BasicHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "myuser|role1,vulcanadmin|8.8.8.8:8||mytenant with whitespace"));
        Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
        Assert.assertTrue(resc.getBody().contains("User [name=myuser, backend_roles=[role1, vulcanadmin], requestedTenant=mytenant with whitespace]"));
        // remote IP is assigned by XFFResolver
        Assert.assertTrue(resc.getBody().contains("\"remote_address\":\"8.8.8.8:8\""));
        Assert.assertTrue(resc.getBody().contains("\"backend_roles\":[\"role1\",\"vulcanadmin\"]"));
        // mapped by backend role "twitter"
        Assert.assertTrue(resc.getBody().contains("\"roles\":[\"public\",\"role_vulcans_admin\"]"));
        

    }    

    @Test
    public void testInjectedUserDisabled() throws Exception {
    
        final Settings settings = Settings.builder()                
                .put("http.type", "org.opensearch.security.http.UserInjectingServerTransport")
                .build();
                      
        setup(settings, ClusterConfiguration.USERINJECTOR);
        
        final RestHelper rh = nonSslRestHelper();
        // username|role1,role2|remoteIP|attributes
        
        HttpResponse resc;
               
        resc = rh.executeGetRequest("_opendistro/_security/authinfo", new BasicHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "admin|role1|127.0.0:80|key1,value1"));
        Assert.assertEquals(HttpStatus.SC_UNAUTHORIZED, resc.getStatusCode());
    }

  @Test
  public void testInjectedAdminUser() throws Exception {
  
      final Settings settings = Settings.builder()                
              .put(ConfigConstants.SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, true)
              .put(ConfigConstants.SECURITY_UNSUPPORTED_INJECT_ADMIN_USER_ENABLED, true)
              .putList(ConfigConstants.SECURITY_AUTHCZ_ADMIN_DN, Lists.newArrayList("CN=kirk,OU=client,O=client,L=Test,C=DE","injectedadmin"))
              .put("http.type", "org.opensearch.security.http.UserInjectingServerTransport")
              .build();
                    
      setup(settings, ClusterConfiguration.USERINJECTOR);
      
      final RestHelper rh = nonSslRestHelper();
      HttpResponse resc;
      
      // injected user is admin, access to Security index must be allowed
      resc = rh.executeGetRequest(".opendistro_security/_search?pretty", new BasicHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "injectedadmin|role1|127.0.0:80|key1,value1"));
      Assert.assertEquals(HttpStatus.SC_OK, resc.getStatusCode());
      Assert.assertTrue(resc.getBody().contains("\"_id\" : \"config\""));
      Assert.assertTrue(resc.getBody().contains("\"_id\" : \"roles\""));
      Assert.assertTrue(resc.getBody().contains("\"_id\" : \"internalusers\""));
      Assert.assertTrue(resc.getBody().contains("\"total\" : 5"));
      
      resc = rh.executeGetRequest(".opendistro_security/_search?pretty", new BasicHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "wrongadmin|role1|127.0.0:80|key1,value1"));
      Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());
      
  }

    @Test
    public void testInjectedAdminUserAdminInjectionDisabled() throws Exception {
    
        final Settings settings = Settings.builder()                
                .put(ConfigConstants.SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, true)
                .putList(ConfigConstants.SECURITY_AUTHCZ_ADMIN_DN, Lists.newArrayList("CN=kirk,OU=client,O=client,L=Test,C=DE","injectedadmin"))
                .put("http.type", "org.opensearch.security.http.UserInjectingServerTransport")
                .build();
                      
        setup(settings, ClusterConfiguration.USERINJECTOR);
        
        final RestHelper rh = nonSslRestHelper();
        HttpResponse resc;
        
        // injected user is admin, access to Security index must be allowed
        resc = rh.executeGetRequest(".opendistro_security/_search?pretty", new BasicHeader(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, "injectedadmin|role1|127.0.0:80|key1,value1"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, resc.getStatusCode());
        Assert.assertFalse(resc.getBody().contains("\"_id\" : \"config\""));
        Assert.assertFalse(resc.getBody().contains("\"_id\" : \"roles\""));
        Assert.assertFalse(resc.getBody().contains("\"_id\" : \"internalusers\""));
        Assert.assertFalse(resc.getBody().contains("\"_id\" : \"tattr\""));
        Assert.assertFalse(resc.getBody(), resc.getBody().contains("\"total\" : 6"));
                
    }    

}
