package com.floragunn.searchguard;

import org.apache.http.HttpStatus;
import org.apache.http.message.BasicHeader;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.test.DynamicSgConfig;
import com.floragunn.searchguard.test.SingleClusterTest;
import com.floragunn.searchguard.test.helper.cluster.ClusterConfiguration;
import com.floragunn.searchguard.test.helper.rest.RestHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper.HttpResponse;

public class LicenseTests extends SingleClusterTest {
    
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
}
