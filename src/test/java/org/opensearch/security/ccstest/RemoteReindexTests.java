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

package org.opensearch.security.ccstest;

import org.opensearch.security.test.AbstractSecurityUnitTest;
import org.apache.http.HttpStatus;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.transport.TransportClient;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;
import org.opensearch.security.test.helper.cluster.ClusterConfiguration;
import org.opensearch.security.test.helper.cluster.ClusterHelper;
import org.opensearch.security.test.helper.cluster.ClusterInfo;
import org.opensearch.security.test.helper.rest.RestHelper;

public class RemoteReindexTests extends AbstractSecurityUnitTest {
    
    private final ClusterHelper cl1 = new ClusterHelper("crl1_n"+num.incrementAndGet()+"_f"+System.getProperty("forkno")+"_t"+System.nanoTime());
    private final ClusterHelper cl2 = new ClusterHelper("crl2_n"+num.incrementAndGet()+"_f"+System.getProperty("forkno")+"_t"+System.nanoTime());
    private ClusterInfo cl1Info;
    private ClusterInfo cl2Info;
    
    private void setupReindex() throws Exception {    
        
        System.setProperty("security.display_lic_none","true");
        
        cl2Info = cl2.startCluster(minimumSecuritySettings(Settings.EMPTY), ClusterConfiguration.DEFAULT);
        initialize(cl2Info);
        
        cl1Info = cl1.startCluster(minimumSecuritySettings(crossClusterNodeSettings(cl2Info)), ClusterConfiguration.DEFAULT);
        initialize(cl1Info);
    }
    
    @After
    public void tearDown() throws Exception {
        cl1.stopCluster();
        cl2.stopCluster();
    }
    
    private Settings crossClusterNodeSettings(ClusterInfo remote) {
        Settings.Builder builder = Settings.builder()
                .putList("reindex.remote.whitelist", remote.httpHost+":"+remote.httpPort);
        return builder.build();
    }
    
    //TODO add ssl tests
    //https://github.com/elastic/elasticsearch/issues/27267
    
    @Test
    public void testNonSSLReindex() throws Exception {
        setupReindex();
        
        final String cl1BodyMain = new RestHelper(cl1Info, false, false, getResourceFolder()).executeGetRequest("", encodeBasicHeader("nagilum","nagilum")).getBody();
        Assert.assertTrue(cl1BodyMain.contains("crl1"));
        
        try (TransportClient tc = getInternalTransportClient(cl1Info, Settings.EMPTY)) {
            tc.admin().indices().create(new CreateIndexRequest("twutter")).actionGet();
        }
        
        final String cl2BodyMain = new RestHelper(cl2Info, false, false, getResourceFolder()).executeGetRequest("", encodeBasicHeader("nagilum","nagilum")).getBody();
        Assert.assertTrue(cl2BodyMain.contains("crl2"));
        
        try (TransportClient tc = getInternalTransportClient(cl2Info, Settings.EMPTY)) {
            tc.index(new IndexRequest("twitter").type("tweet").setRefreshPolicy(RefreshPolicy.IMMEDIATE).id("0")
                    .source("{\"cluster\": \""+cl1Info.clustername+"\"}", XContentType.JSON)).actionGet();
        }
        
        String reindex = "{"+
            "\"source\": {"+
                "\"remote\": {"+
                "\"host\": \"http://"+cl2Info.httpHost+":"+cl2Info.httpPort+"\","+
                "\"username\": \"nagilum\","+
                "\"password\": \"nagilum\""+
                  "},"+
                    "\"index\": \"twitter\","+
                    "\"size\": 10,"+
                    "\"query\": {"+
                    "\"match\": {"+
                    "\"_type\": \"tweet\""+
                    "}"+
                  "}"+
            "},"+
                "\"dest\": {"+
                "\"index\": \"twutter\""+
            "}"+
        "}";
        
        System.out.println(reindex);
        
        HttpResponse ccs = null;
        
        System.out.println("###################### reindex");
        ccs = new RestHelper(cl1Info, false, false, getResourceFolder()).executePostRequest("_reindex?pretty", reindex, encodeBasicHeader("nagilum","nagilum"));
        System.out.println(ccs.getBody());
        Assert.assertEquals(HttpStatus.SC_OK, ccs.getStatusCode());
        Assert.assertTrue(ccs.getBody().contains("created\" : 1"));
    }
}
