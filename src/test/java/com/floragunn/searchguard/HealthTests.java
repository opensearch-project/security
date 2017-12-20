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
