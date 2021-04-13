package com.amazon.opendistroforelasticsearch.security.dlic.dlsfls;

import org.apache.http.HttpStatus;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.xcontent.XContentType;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class DlsNoDlsAndDlsAtTheSameTime extends AbstractDlsFlsTest{

    // ## How have these tests been built ?? ##
    // Tests for PR #1078 and Issue #13
    // https://github.com/opendistro-for-elasticsearch/security/pull/1078
    // The idea here is to make sure that when a user has 2 or more distinct roles
    // pointing at the same indices via index patterns that are either directly
    // declared, via wilcards or via user attributes, if one of those roles has NO
    // DLS declared, that we make sure that the user has access to ALL the documents
    // of these indices.
    // Tests are organized like this :
    // * user : user_with_dls_and_no_dls_at_the_same_time (declared in internal_users.yml
    // declared in the corresponding resources folder)
    // * roles (declared in roles.yml in the corresponding resources folder):
    //   - opendistro_no_dls : role pointing to the test indices with no DLS declared
    //   - opendistro_dls : role pointing to the test indices with no DLS declared
    // * indices :
    //   - dls_no_dls_index_simple : this index is directly declared in the index patterns of the role def
    //   - dls_no_dls_index_wildcard : can be declared in the index patterns of the role def via a wildcard
    //   - dls_no_dls_index_attribute : can be declared in the index patterns of the role def via a user attribute substitution
    //   - dls_no_dls_index_mixed : can ne declared in the index patterns via a user attribute substitution plus a wildcard
    //   - dls_no_dls_only_dls : This index is used to ensure that the dls is working and will filter on documents with field1 = value1

    // our test indices variable
    List<String> indices_with_dls_and_no_dls = Arrays.asList("dls_no_dls_index_simple",
                                                             "dls_no_dls_index_wildcard",
                                                             "dls_no_dls_index_attribute",
                                                             "dls_no_dls_index_mixed");

    String index_with_only_dls = "dls_no_dls_only_dls" ;


    protected void populateData(TransportClient tc) {

        // Create indices that are pointed by both role with dls and no dls at the same time
        List <String> all_indices = new ArrayList<>(indices_with_dls_and_no_dls);
        all_indices.add(index_with_only_dls) ;

        all_indices.forEach((index) -> {
        tc.index(new IndexRequest(index).type("_doc").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"field1\": \"value1\", \"id\": 1}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest(index).type("_doc").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"field1\": \"value2\", \"id\": 2}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest(index).type("_doc").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"field1\": \"value3\", \"id\": 3}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest(index).type("_doc").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
                .source("{\"field1\": \"value1\", \"id\": 4}", XContentType.JSON)).actionGet();
        });
    }

    @Test
    public void testDlsAccess() throws Exception {

        setup();

        HttpResponse res;
        String current_index = "" ;
        // Loop through our indices that are pointed by both role with dls and no dls at the same time
        for (int i = 0; i < indices_with_dls_and_no_dls.size() ; i++) {
            try {
                current_index = indices_with_dls_and_no_dls.get(i);
                res = rh.executeGetRequest("/"+current_index+"/_search?pretty",
                                           encodeBasicHeader("user_with_dls_and_no_dls_at_the_same_time",
                                                   "user_with_dls_and_no_dls_at_the_same_time")) ;
                System.out.println("###>>>### Test : DlsNoDlsAndDlsAtTheSameTime ### Tested Index "+current_index+", Response Body // Start // : ");

                Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());

                System.out.println(res.getBody());
                System.out.println("###<<<### Test : DlsNoDlsAndDlsAtTheSameTime ### Tested Index "+current_index+", Response Body // End //");
                Assert.assertTrue(res.getBody().contains("\"id\" : 1"));
                Assert.assertTrue(res.getBody().contains("\"id\" : 2"));
                Assert.assertTrue(res.getBody().contains("\"id\" : 3"));
                Assert.assertTrue(res.getBody().contains("\"id\" : 4"));

            } catch(Exception e) {
                System.out.println("###!!!>>>### Test : DlsNoDlsAndDlsAtTheSameTime ### Tested Index "+current_index+", Exception :" );
                System.out.println(e.toString());
                System.out.println("###!!!<<<### Test : DlsNoDlsAndDlsAtTheSameTime ### Tested Index "+current_index+", Exception :" );
            }
        }

        // Ensure dls is working with index pointed only by dls.
        String index = index_with_only_dls ;
        try {
            res = rh.executeGetRequest("/"+index+"/_search?pretty",
                    encodeBasicHeader("user_with_dls_and_no_dls_at_the_same_time",
                            "user_with_dls_and_no_dls_at_the_same_time")) ;
            System.out.println("###>>>### Test : DlsNoDlsAndDlsAtTheSameTime ### Tested Index "+index+", Response Body // Start // : ");

            Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());

            System.out.println(res.getBody());
            System.out.println("###<<<### Test : DlsNoDlsAndDlsAtTheSameTime ### Tested Index "+index+", Response Body // End //");
            Assert.assertTrue(res.getBody().contains("\"id\" : 1"));
            Assert.assertTrue(! res.getBody().contains("\"id\" : 2"));
            Assert.assertTrue(! res.getBody().contains("\"id\" : 3"));
            Assert.assertTrue(res.getBody().contains("\"id\" : 4"));

        } catch(Exception e) {
            System.out.println("###!!!>>>### Test : DlsNoDlsAndDlsAtTheSameTime ### Tested Index "+index+", Exception :" );
            System.out.println(e.toString());
            System.out.println("###!!!<<<### Test : DlsNoDlsAndDlsAtTheSameTime ### Tested Index "+index+", Exception :" );
        }
    }
}

