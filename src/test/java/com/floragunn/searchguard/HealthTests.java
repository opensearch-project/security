package com.floragunn.searchguard;

import org.apache.http.HttpStatus;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.test.DynamicSgConfig;
import com.floragunn.searchguard.test.SingleClusterTest;
import com.floragunn.searchguard.test.helper.rest.RestHelper;
import com.floragunn.searchguard.test.helper.rest.RestHelper.HttpResponse;

public class HealthTests extends SingleClusterTest {
    
    @Test
    public void testHealth() throws Exception {
        setup(Settings.EMPTY, new DynamicSgConfig(), Settings.EMPTY);
        
        RestHelper rh = nonSslRestHelper();
        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_searchguard/health?pretty&mode=lenient")).getStatusCode());
        System.out.println(res.getBody());
        assertContains(res, "*UP*");
        assertNotContains(res, "*DOWN*");
        assertNotContains(res, "*strict*");
        
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_searchguard/health?pretty")).getStatusCode());
        System.out.println(res.getBody());
        assertContains(res, "*UP*");
        assertContains(res, "*strict*");
        assertNotContains(res, "*DOWN*");
    }
    
    @Test
    public void testHealthUnitialized() throws Exception {
        setup(Settings.EMPTY, null, Settings.EMPTY, false);
        
        RestHelper rh = nonSslRestHelper();
        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_searchguard/health?pretty&mode=lenient")).getStatusCode());
        System.out.println(res.getBody());
        assertContains(res, "*UP*");
        assertNotContains(res, "*DOWN*");
        assertNotContains(res, "*strict*");
        
        Assert.assertEquals(HttpStatus.SC_SERVICE_UNAVAILABLE, (res = rh.executeGetRequest("_searchguard/health?pretty")).getStatusCode());
        System.out.println(res.getBody());
        assertContains(res, "*DOWN*");
        assertContains(res, "*strict*");
        assertNotContains(res, "*UP*");
    }
}
