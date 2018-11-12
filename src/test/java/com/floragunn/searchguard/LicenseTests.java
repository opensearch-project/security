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

package com.floragunn.searchguard;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.text.SimpleDateFormat;
import java.util.Date;

import org.apache.http.HttpStatus;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.node.DiscoveryNodes;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import com.floragunn.searchguard.configuration.SearchGuardLicense;
import com.floragunn.searchguard.configuration.SearchGuardLicense.Feature;
import com.floragunn.searchguard.test.DynamicSgConfig;
import com.floragunn.searchguard.test.SingleClusterTest;
import com.floragunn.searchguard.test.helper.file.FileHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper.HttpResponse;

public class LicenseTests extends SingleClusterTest {
    
    ClusterService cs = mock(ClusterService.class);
    DiscoveryNodes dns = mock(DiscoveryNodes.class);
    ClusterState cstate = mock(ClusterState.class);

    @Before
    public void setup() {
        when(dns.getSize()).thenReturn(10);
        when(cstate.getNodes()).thenReturn(dns);
        when(cs.state()).thenReturn(cstate);
    }
    
    @Test
    public void testInvalidLicense() throws Exception {
        setup(Settings.EMPTY, new DynamicSgConfig().setSgConfig("sg_config_invalidlic.yml"), Settings.EMPTY);
        
        RestHelper rh = nonSslRestHelper();
        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_searchguard/license?pretty")).getStatusCode());
        System.out.println(res.getBody());
        assertContains(res, "*TRIAL*");
        assertContains(res, "*Invalid license signature*");
        assertNotContains(res, "*FULL*");
    }
    
    @Test
    public void testTrialLicense() throws Exception {
        setup(Settings.EMPTY, new DynamicSgConfig(), Settings.EMPTY);
        
        RestHelper rh = nonSslRestHelper();
        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_searchguard/license?pretty")).getStatusCode());
        System.out.println(res.getBody());
        assertContains(res, "*TRIAL*");
        assertNotContains(res, "*FULL*");
    }
    
    @Test
    public void testFullLicense() throws Exception {
        setup(Settings.EMPTY, new DynamicSgConfig().setSgConfig("sg_config_lic.yml"), Settings.EMPTY);
        
        RestHelper rh = nonSslRestHelper();
        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_searchguard/license?pretty", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("FULL"));
        Assert.assertTrue(res.getBody().contains("is_valid\" : true"));
    }
    
    @Test
    public void testComplianceLicense() throws Exception {
      
        final String now = new SimpleDateFormat("yyyy-MM-dd").format(new Date());
        SearchGuardLicense license = SearchGuardLicense.createTrialLicense(now, cs, "");
        
        Assert.assertTrue(license.hasFeature(Feature.COMPLIANCE));
        Assert.assertArrayEquals(license.getFeatures(), Feature.values());
        Assert.assertTrue(license.isValid());
        Assert.assertFalse(license.isExpired());
        Assert.assertEquals(60, license.getExpiresInDays());
    }
    
    @Test
    public void testComplianceLicenseMap() throws Exception {

        SearchGuardLicense license = new SearchGuardLicense(XContentHelper
                .convertToMap(new BytesArray(FileHelper.loadFile("license1.json")), false, JsonXContent.jsonXContent.type()).v2(), cs);
        
        Assert.assertFalse(license.hasFeature(Feature.COMPLIANCE));
        Assert.assertArrayEquals(license.getFeatures(), new Feature[0]);
        
        license = new SearchGuardLicense(XContentHelper
                .convertToMap(new BytesArray(FileHelper.loadFile("license3.json")), false, JsonXContent.jsonXContent.type()).v2(), cs);
        
        Assert.assertFalse(license.hasFeature(Feature.COMPLIANCE));
        Assert.assertArrayEquals(license.getFeatures(), new Feature[0]);
        
        license = new SearchGuardLicense(XContentHelper
                .convertToMap(new BytesArray(FileHelper.loadFile("license2.json")), false, JsonXContent.jsonXContent.type()).v2(), cs);
        
        Assert.assertTrue(license.hasFeature(Feature.COMPLIANCE));
        Assert.assertArrayEquals(license.getFeatures(), Feature.values());
    }

    @Test
    public void testFullLicenseRK() throws Exception {
        setup(Settings.EMPTY, new DynamicSgConfig().setSgConfig("sg_config_lic_rk.yml"), Settings.EMPTY);
        
        RestHelper rh = nonSslRestHelper();
        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_searchguard/license?pretty", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("FULL"));
        Assert.assertTrue(res.getBody().contains("is_valid\" : true"));
    }
    
    @Test
    public void testFullLicenseReload() throws Exception {
        setup(Settings.EMPTY, new DynamicSgConfig().setSgConfig("sg_config_lic.yml"), Settings.EMPTY);
        
        RestHelper rh = nonSslRestHelper();
        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_searchguard/license?pretty", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("FULL"));
        Assert.assertTrue(res.getBody().contains("is_valid\" : true"));
        
        initialize(clusterInfo, Settings.EMPTY, new DynamicSgConfig());

        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_searchguard/license?pretty", encodeBasicHeader("nagilum", "nagilum"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().contains("FULL"));
        Assert.assertFalse(res.getBody().contains("TRIAL"));
        Assert.assertTrue(res.getBody().contains("is_valid\" : true"));
    }
}
