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

package com.amazon.opendistroforelasticsearch.security;

import org.apache.http.HttpStatus;
import org.apache.http.message.BasicHeader;
import org.opensearch.common.settings.Settings;
import org.opensearch.tasks.Task;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.test.DynamicSecurityConfig;
import com.amazon.opendistroforelasticsearch.security.test.SingleClusterTest;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;

public class TaskTests extends SingleClusterTest {
    
    @Test
    public void testXOpaqueIdHeader() throws Exception {
        setup(Settings.EMPTY, new DynamicSecurityConfig(), Settings.EMPTY);
        
        RestHelper rh = nonSslRestHelper();
        HttpResponse res;
        Assert.assertEquals(HttpStatus.SC_OK, (res = rh.executeGetRequest("_tasks?group_by=parents&pretty"
                , encodeBasicHeader("nagilum", "nagilum")
                , new BasicHeader(Task.X_OPAQUE_ID, "myOpaqueId12"))).getStatusCode());
        System.out.println(res.getBody());
        Assert.assertTrue(res.getBody().split("X-Opaque-Id").length > 2);
        Assert.assertTrue(!res.getBody().contains("failures"));
    }
}
