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

package org.opensearch.security.dlic.dlsfls;

import static org.opensearch.security.dlic.dlsfls.DlsTermsLookupAsserts.assertAccessCodesMatch;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.Assert;
import org.junit.Test;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.get.MultiGetItemResponse;
import org.opensearch.action.get.MultiGetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.MultiSearchResponse;
import org.opensearch.action.search.MultiSearchResponse.Item;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.client.transport.TransportClient;
import org.opensearch.common.ParseField;
import org.opensearch.common.xcontent.ContextParser;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.search.SearchHit;
import org.opensearch.search.aggregations.Aggregation;
import org.opensearch.search.aggregations.Aggregations;
import org.opensearch.search.aggregations.bucket.terms.ParsedStringTerms;
import org.opensearch.search.aggregations.bucket.terms.StringTerms;
import org.opensearch.search.aggregations.bucket.terms.Terms;
import org.opensearch.search.aggregations.bucket.terms.Terms.Bucket;
import org.opensearch.search.aggregations.metrics.ParsedTopHits;
import org.opensearch.search.aggregations.metrics.TopHitsAggregationBuilder;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;

public class DlsTermLookupQueryTest extends AbstractDlsFlsTest {

	protected void populateData(Client client) {
		// user access codes, basis for TLQ query
		client.index(new IndexRequest("user_access_codes").id("tlq_1337").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"access_codes\": [1337] }", XContentType.JSON)).actionGet();
		client.index(new IndexRequest("user_access_codes").id("tlq_42").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"access_codes\": [42] }", XContentType.JSON)).actionGet();
		client.index(new IndexRequest("user_access_codes").id("tlq_1337_42").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"access_codes\": [1337, 42] }", XContentType.JSON)).actionGet();
		client.index(new IndexRequest("user_access_codes").id("tlq_999").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"access_codes\": [999] }", XContentType.JSON)).actionGet();
		client.index(new IndexRequest("user_access_codes").id("tlq_empty_access_codes")
				.setRefreshPolicy(RefreshPolicy.IMMEDIATE).source("{ \"access_codes\": [] }", XContentType.JSON))
				.actionGet();
		client.index(new IndexRequest("user_access_codes").id("tlq_no_codes").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"bla\": \"blub\" }", XContentType.JSON)).actionGet();

		// need to have keyword for bu field since we're testing aggregations
		client.admin().indices().create(new CreateIndexRequest("tlqdocuments")).actionGet();
		client.admin().indices()
				.putMapping(new PutMappingRequest("tlqdocuments").type("_doc").source("bu", "type=keyword"))
				.actionGet();

		// tlqdocuments, protected by TLQ
		client.index(new IndexRequest("tlqdocuments").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"bu\": \"AAA\", \"access_codes\": [1337] }", XContentType.JSON)).actionGet();
		client.index(new IndexRequest("tlqdocuments").id("2").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"bu\": \"AAA\", \"access_codes\": [42] }", XContentType.JSON)).actionGet();
		client.index(new IndexRequest("tlqdocuments").id("3").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"bu\": \"AAA\", \"access_codes\": [1337, 42] }", XContentType.JSON)).actionGet();
		client.index(new IndexRequest("tlqdocuments").id("4").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"bu\": \"BBB\", \"access_codes\": [1337] }", XContentType.JSON)).actionGet();
		client.index(new IndexRequest("tlqdocuments").id("5").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"bu\": \"BBB\", \"access_codes\": [42] }", XContentType.JSON)).actionGet();
		client.index(new IndexRequest("tlqdocuments").id("6").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"bu\": \"BBB\", \"access_codes\": [1337, 42] }", XContentType.JSON)).actionGet();
		client.index(new IndexRequest("tlqdocuments").id("7").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"bu\": \"CCC\", \"access_codes\": [1337] }", XContentType.JSON)).actionGet();
		client.index(new IndexRequest("tlqdocuments").id("8").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"bu\": \"CCC\", \"access_codes\": [42] }", XContentType.JSON)).actionGet();
		client.index(new IndexRequest("tlqdocuments").id("9").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"bu\": \"CCC\", \"access_codes\": [1337, 42] }", XContentType.JSON)).actionGet();
		client.index(new IndexRequest("tlqdocuments").id("10").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"bu\": \"DDD\", \"access_codes\": [1337] }", XContentType.JSON)).actionGet();
		client.index(new IndexRequest("tlqdocuments").id("11").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"bu\": \"DDD\", \"access_codes\": [42] }", XContentType.JSON)).actionGet();
		client.index(new IndexRequest("tlqdocuments").id("12").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"bu\": \"DDD\", \"access_codes\": [1337, 42] }", XContentType.JSON)).actionGet();
		client.index(new IndexRequest("tlqdocuments").id("13").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"bu\": \"EEE\", \"access_codes\": [1337] }", XContentType.JSON)).actionGet();
		client.index(new IndexRequest("tlqdocuments").id("14").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"bu\": \"EEE\", \"access_codes\": [42] }", XContentType.JSON)).actionGet();
		client.index(new IndexRequest("tlqdocuments").id("15").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"bu\": \"EEE\", \"access_codes\": [1337, 42] }", XContentType.JSON)).actionGet();
		client.index(new IndexRequest("tlqdocuments").id("16").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"bu\": \"FFF\" }", XContentType.JSON)).actionGet();
		client.index(new IndexRequest("tlqdocuments").id("17").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"bu\": \"FFF\", \"access_codes\": [12345] }", XContentType.JSON)).actionGet();
		client.index(new IndexRequest("tlqdocuments").id("18").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"bu\": \"FFF\", \"access_codes\": [12345, 6789] }", XContentType.JSON)).actionGet();

		// we use a "bu" field here as well to test aggregations over multiple indices
		client.admin().indices().create(new CreateIndexRequest("tlqdummy")).actionGet();
		client.admin().indices().putMapping(new PutMappingRequest("tlqdummy").type("_doc").source("bu", "type=keyword"))
				.actionGet();

		// tlqdummy, not protected by TLQ
		client.index(new IndexRequest("tlqdummy").id("101").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"mykey\": \"101\", \"bu\": \"GGG\" }", XContentType.JSON)).actionGet();
		client.index(new IndexRequest("tlqdummy").id("102").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"mykey\": \"102\", \"bu\": \"GGG\" }", XContentType.JSON)).actionGet();
		client.index(new IndexRequest("tlqdummy").id("103").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"mykey\": \"103\", \"bu\": \"GGG\" }", XContentType.JSON)).actionGet();
		client.index(new IndexRequest("tlqdummy").id("104").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"mykey\": \"104\", \"bu\": \"GGG\" }", XContentType.JSON)).actionGet();
		client.index(new IndexRequest("tlqdummy").id("105").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
				.source("{ \"mykey\": \"105\", \"bu\": \"GGG\" }", XContentType.JSON)).actionGet();

	}

	// ------------------------
	// Test search and msearch
	// ------------------------

	@Test
	public void testSimpleSearch_AccessCode_1337() throws Exception {

		setup(new DynamicSecurityConfig().setConfig("securityconfig_tlq.yml")
				.setSecurityInternalUsers("internal_users_tlq.yml").setSecurityRoles("roles_tlq.yml")
				.setSecurityRolesMapping("roles_mapping_tlq.yml"));

		HttpResponse response = rh.executeGetRequest("/tlqdocuments/_search?pretty",
				encodeBasicHeader("tlq_1337", "password"));
		Assert.assertEquals(200, response.getStatusCode());
		XContentParser xcp = XContentType.JSON.xContent().createParser(NamedXContentRegistry.EMPTY,
				LoggingDeprecationHandler.INSTANCE, response.getBody());
		SearchResponse searchResponse = SearchResponse.fromXContent(xcp);
		// 10 docs, all need to have access code 1337
		Assert.assertEquals(searchResponse.toString(), 10, searchResponse.getHits().getTotalHits().value);
		// fields need to have 1337 access code
		assertAccessCodesMatch(searchResponse.getHits().getHits(), new Integer[] { 1337 });
	}

	@Test
	public void testSimpleSearch_AccessCode_42() throws Exception {

		setup(new DynamicSecurityConfig().setConfig("securityconfig_tlq.yml")
				.setSecurityInternalUsers("internal_users_tlq.yml").setSecurityRoles("roles_tlq.yml")
				.setSecurityRolesMapping("roles_mapping_tlq.yml"));

		HttpResponse response = rh.executeGetRequest("/tlqdocuments/_search?pretty",
				encodeBasicHeader("tlq_42", "password"));
		Assert.assertEquals(200, response.getStatusCode());
		XContentParser xcp = XContentType.JSON.xContent().createParser(NamedXContentRegistry.EMPTY,
				LoggingDeprecationHandler.INSTANCE, response.getBody());
		SearchResponse searchResponse = SearchResponse.fromXContent(xcp);

		// 10 docs, all need to have access code 42
		Assert.assertEquals(searchResponse.toString(), 10, searchResponse.getHits().getTotalHits().value);
		// fields need to have 42 access code
		assertAccessCodesMatch(searchResponse.getHits().getHits(), new Integer[] { 42 });

	}

	@Test
	public void testSimpleSearch_AccessCodes_1337_42() throws Exception {

		setup(new DynamicSecurityConfig().setConfig("securityconfig_tlq.yml")
				.setSecurityInternalUsers("internal_users_tlq.yml").setSecurityRoles("roles_tlq.yml")
				.setSecurityRolesMapping("roles_mapping_tlq.yml"));

		HttpResponse response = rh.executeGetRequest("/tlqdocuments/_search?pretty",
				encodeBasicHeader("tlq_1337_42", "password"));
		Assert.assertEquals(200, response.getStatusCode());
		XContentParser xcp = XContentType.JSON.xContent().createParser(NamedXContentRegistry.EMPTY,
				LoggingDeprecationHandler.INSTANCE, response.getBody());
		SearchResponse searchResponse = SearchResponse.fromXContent(xcp);

		// 15 docs, all need to have either access code 1337 or 42
		Assert.assertEquals(searchResponse.toString(), 15, searchResponse.getHits().getTotalHits().value);
		// fields need to have 42 or 1337 access code
		assertAccessCodesMatch(searchResponse.getHits().getHits(), new Integer[] { 42, 1337 });

	}

	@Test
	public void testSimpleSearch_AccessCodes_999() throws Exception {

		setup(new DynamicSecurityConfig().setConfig("securityconfig_tlq.yml")
				.setSecurityInternalUsers("internal_users_tlq.yml").setSecurityRoles("roles_tlq.yml")
				.setSecurityRolesMapping("roles_mapping_tlq.yml"));

		HttpResponse response = rh.executeGetRequest("/tlqdocuments/_search?pretty",
				encodeBasicHeader("tlq_999", "password"));
		Assert.assertEquals(200, response.getStatusCode());
		XContentParser xcp = XContentType.JSON.xContent().createParser(NamedXContentRegistry.EMPTY,
				LoggingDeprecationHandler.INSTANCE, response.getBody());
		SearchResponse searchResponse = SearchResponse.fromXContent(xcp);

		Assert.assertEquals(searchResponse.toString(), 0, searchResponse.getHits().getTotalHits().value);
	}

	@Test
	public void testSimpleSearch_AccessCodes_emptyAccessCodes() throws Exception {

		setup(new DynamicSecurityConfig().setConfig("securityconfig_tlq.yml")
				.setSecurityInternalUsers("internal_users_tlq.yml").setSecurityRoles("roles_tlq.yml")
				.setSecurityRolesMapping("roles_mapping_tlq.yml"));
		SearchResponse searchResponse = executeSearch("tlqdocuments", "tlq_empty_access_codes", "password");
		Assert.assertEquals(searchResponse.toString(), 0, searchResponse.getHits().getTotalHits().value);
	}

	@Test
	public void testSimpleSearch_AccessCodes_noAccessCodes() throws Exception {

		setup(new DynamicSecurityConfig().setConfig("securityconfig_tlq.yml")
				.setSecurityInternalUsers("internal_users_tlq.yml").setSecurityRoles("roles_tlq.yml")
				.setSecurityRolesMapping("roles_mapping_tlq.yml"));
		SearchResponse searchResponse = executeSearch("tlqdocuments", "tlq_no_codes", "password");

		Assert.assertEquals(searchResponse.toString(), 0, searchResponse.getHits().getTotalHits().value);
	}

	@Test
	public void testSimpleSearch_AllIndices_All_AccessCodes_1337() throws Exception {
		setup(new DynamicSecurityConfig().setConfig("securityconfig_tlq.yml")
				.setSecurityInternalUsers("internal_users_tlq.yml").setSecurityRoles("roles_tlq.yml")
				.setSecurityRolesMapping("roles_mapping_tlq.yml"));

		SearchResponse searchResponse = executeSearch("_all", "tlq_1337", "password");

		// assume hits from 2 indices:
		// - tlqdocuments, must contain only docs with access code 1337
		// - tlqdummy, contains all documents
		// no access to user_access_codes must be granted

		// check all 5 tlqdummy entries present, index is not protected by DLS
		Set<SearchHit> tlqdummyHits = Arrays.asList(searchResponse.getHits().getHits()).stream()
				.filter((h) -> h.getIndex().equals("tlqdummy")).collect(Collectors.toSet());
		Assert.assertEquals(searchResponse.toString(), 5, tlqdummyHits.size());

		// check 10 hits with code 1337 from tlqdocuments index. All other documents
		// must be filtered
		Set<SearchHit> tlqdocumentHits = Arrays.asList(searchResponse.getHits().getHits()).stream()
				.filter((h) -> h.getIndex().equals("tlqdocuments")).collect(Collectors.toSet());
		Assert.assertEquals(searchResponse.toString(), 10, tlqdocumentHits.size());
		assertAccessCodesMatch(tlqdocumentHits, new Integer[] { 1337 });

		// check no access to user_access_codes index
		Set<SearchHit> userAccessCodesHits = Arrays.asList(searchResponse.getHits().getHits()).stream()
				.filter((h) -> h.getIndex().equals("user_access_codes")).collect(Collectors.toSet());
		Assert.assertEquals(searchResponse.toString(), 0, userAccessCodesHits.size());
	}

	@Test
	public void testSimpleSearch_AllIndicesWildcard_AccessCodes_1337() throws Exception {

		setup(new DynamicSecurityConfig().setConfig("securityconfig_tlq.yml")
				.setSecurityInternalUsers("internal_users_tlq.yml").setSecurityRoles("roles_tlq.yml")
				.setSecurityRolesMapping("roles_mapping_tlq.yml"));

		SearchResponse searchResponse = executeSearch("*", "tlq_1337", "password");

		// assume hits from 2 indices:
		// - tlqdocuments, must contain only docs with access code 1337
		// - tlqdummy, contains all documents
		// no access to user_access_codes must be granted

		// check all 5 tlqdummy entries present, index is not protected by DLS
		Set<SearchHit> tlqdummyHits = Arrays.asList(searchResponse.getHits().getHits()).stream()
				.filter((h) -> h.getIndex().equals("tlqdummy")).collect(Collectors.toSet());
		Assert.assertEquals(searchResponse.toString(), 5, tlqdummyHits.size());

		// check 10 hits with code 1337 from tlqdocuments index. All other documents
		// must be filtered
		Set<SearchHit> tlqdocumentHits = Arrays.asList(searchResponse.getHits().getHits()).stream()
				.filter((h) -> h.getIndex().equals("tlqdocuments")).collect(Collectors.toSet());
		Assert.assertEquals(searchResponse.toString(), 10, tlqdocumentHits.size());
		assertAccessCodesMatch(tlqdocumentHits, new Integer[] { 1337 });

		// check no access to user_access_codes index
		Set<SearchHit> userAccessCodesHits = Arrays.asList(searchResponse.getHits().getHits()).stream()
				.filter((h) -> h.getIndex().equals("user_access_codes")).collect(Collectors.toSet());
		Assert.assertEquals(searchResponse.toString(), 0, userAccessCodesHits.size());
	}

	@Test
	public void testSimpleSearch_ThreeIndicesWildcard_AccessCodes_1337() throws Exception {

		setup(new DynamicSecurityConfig().setConfig("securityconfig_tlq.yml")
				.setSecurityInternalUsers("internal_users_tlq.yml").setSecurityRoles("roles_tlq.yml")
				.setSecurityRolesMapping("roles_mapping_tlq.yml"));

		SearchResponse searchResponse = executeSearch("tlq*,user*", "tlq_1337", "password");

		// assume hits from 2 indices:
		// - tlqdocuments, must contain only docs with access code 1337
		// - tlqdummy, contains all documents
		// no access to user_access_codes must be granted

		// check all 5 tlqdummy entries present, index is not protected by DLS
		Set<SearchHit> tlqdummyHits = Arrays.asList(searchResponse.getHits().getHits()).stream()
				.filter((h) -> h.getIndex().equals("tlqdummy")).collect(Collectors.toSet());
		Assert.assertEquals(searchResponse.toString(), 5, tlqdummyHits.size());

		// check 10 hits with code 1337 from tlqdocuments index. All other documents
		// must be filtered
		Set<SearchHit> tlqdocumentHits = Arrays.asList(searchResponse.getHits().getHits()).stream()
				.filter((h) -> h.getIndex().equals("tlqdocuments")).collect(Collectors.toSet());
		Assert.assertEquals(searchResponse.toString(), 10, tlqdocumentHits.size());
		assertAccessCodesMatch(tlqdocumentHits, new Integer[] { 1337 });

		// check no access to user_access_codes index
		Set<SearchHit> userAccessCodesHits = Arrays.asList(searchResponse.getHits().getHits()).stream()
				.filter((h) -> h.getIndex().equals("user_access_codes")).collect(Collectors.toSet());
		Assert.assertEquals(searchResponse.toString(), 0, userAccessCodesHits.size());

	}

	@Test
	public void testSimpleSearch_TwoIndicesConcreteNames_AccessCodes_1337() throws Exception {

		setup(new DynamicSecurityConfig().setConfig("securityconfig_tlq.yml")
				.setSecurityInternalUsers("internal_users_tlq.yml").setSecurityRoles("roles_tlq.yml")
				.setSecurityRolesMapping("roles_mapping_tlq.yml"));

		SearchResponse searchResponse = executeSearch("tlqdocuments,tlqdummy", "tlq_1337", "password");

		// assume hits from 2 indices:
		// - tlqdocuments, must contains only 10 docs with access code 1337
		// - tlqdummy, must contains all 5 documents

		// check all 5 tlqdummy entries present, index is not protected by DLS
		Set<SearchHit> tlqdummyHits = Arrays.asList(searchResponse.getHits().getHits()).stream()
				.filter((h) -> h.getIndex().equals("tlqdummy")).collect(Collectors.toSet());
		Assert.assertEquals(searchResponse.toString(), 5, tlqdummyHits.size());

		// ccheck 10 hits with code 1337 from tlqdocuments index. All other documents
		// must be filtered
		Set<SearchHit> tlqdocumentHits = Arrays.asList(searchResponse.getHits().getHits()).stream()
				.filter((h) -> h.getIndex().equals("tlqdocuments")).collect(Collectors.toSet());
		Assert.assertEquals(searchResponse.toString(), 10, tlqdocumentHits.size());
		assertAccessCodesMatch(tlqdocumentHits, new Integer[] { 1337 });
	}

	@Test
	public void testMSearch_ThreeIndices_AccessCodes_1337() throws Exception {

		setup(new DynamicSecurityConfig().setConfig("securityconfig_tlq.yml")
				.setSecurityInternalUsers("internal_users_tlq.yml").setSecurityRoles("roles_tlq.yml")
				.setSecurityRolesMapping("roles_mapping_tlq.yml"));

		MultiSearchResponse searchResponse = executeMSearchMatchAll("tlq_1337", "password", "tlqdummy", "tlqdocuments",
				"user_access_codes");

		Item[] responseItems = searchResponse.getResponses();

		// as per API order in response is the same as in the msearch request

		// check all 5 tlqdummy entries present
		List<SearchHit> tlqdummyHits = Arrays.asList(responseItems[0].getResponse().getHits().getHits());
		Assert.assertEquals(searchResponse.toString(), 5, tlqdummyHits.size());

		// check 10 hits with code 1337 from tlqdocuments index. All other documents
		// must be filtered
		List<SearchHit> tlqdocumentHits = Arrays.asList(responseItems[1].getResponse().getHits().getHits());
		Assert.assertEquals(searchResponse.toString(), 10, tlqdocumentHits.size());
		assertAccessCodesMatch(tlqdocumentHits, new Integer[] { 1337 });

		// check no access to user_access_codes index, just two indices in the response
		Assert.assertTrue(responseItems[2].getResponse() == null);
		Assert.assertTrue(responseItems[2].getFailure() != null);

	}

	// ------------------------
	// Test get and mget
	// ------------------------

	@Test
	public void testGet_TlqDocumentsIndex_1337() throws Exception {

		setup(new DynamicSecurityConfig().setConfig("securityconfig_tlq.yml")
				.setSecurityInternalUsers("internal_users_tlq.yml").setSecurityRoles("roles_tlq.yml")
				.setSecurityRolesMapping("roles_mapping_tlq.yml"));

		// user has 1337, document has 1337
		GetResponse searchResponse = executeGet("tlqdocuments", "1", "tlq_1337", "password");
		Assert.assertTrue(searchResponse != null);
		Assert.assertTrue(searchResponse.isExists());
		assertAccessCodesMatch(searchResponse.getSourceAsMap(), "access_codes", new Integer[] { 1337 });

		// user has 1337, document has 42, not visible
		searchResponse = executeGet("tlqdocuments", "2", "tlq_1337", "password");
		Assert.assertFalse(searchResponse.isExists());

		// user has 1337, document has 42 and 1337
		searchResponse = executeGet("tlqdocuments", "3", "tlq_1337", "password");
		Assert.assertTrue(searchResponse != null);
		Assert.assertTrue(searchResponse.isExists());
		assertAccessCodesMatch(searchResponse.getSourceAsMap(), "access_codes", new Integer[] { 1337 });

		// user has 1337, document has no access codes, not visible
		searchResponse = executeGet("tlqdocuments", "16", "tlq_1337", "password");
		Assert.assertFalse(searchResponse.isExists());

		// user has 1337, document has 12345, not visible
		searchResponse = executeGet("tlqdocuments", "17", "tlq_1337", "password");
		Assert.assertFalse(searchResponse.isExists());

		// user has 1337, document has 12345 and 6789, not visible
		searchResponse = executeGet("tlqdocuments", "18", "tlq_1337", "password");
		Assert.assertFalse(searchResponse.isExists());

	}

	@Test
	public void testGet_TlqDocumentsIndex_1337_42() throws Exception {

		setup(new DynamicSecurityConfig().setConfig("securityconfig_tlq.yml")
				.setSecurityInternalUsers("internal_users_tlq.yml").setSecurityRoles("roles_tlq.yml")
				.setSecurityRolesMapping("roles_mapping_tlq.yml"));

		// user has 1337 and 42, document has 1337
		GetResponse searchResponse = executeGet("tlqdocuments", "1", "tlq_1337_42", "password");
		Assert.assertTrue(searchResponse != null);
		Assert.assertTrue(searchResponse.isExists());
		assertAccessCodesMatch(searchResponse.getSourceAsMap(), "access_codes", new Integer[] { 1337, 42 });

		// user has 1337 and 42, document has 42
		searchResponse = executeGet("tlqdocuments", "2", "tlq_1337_42", "password");
		Assert.assertTrue(searchResponse != null);
		Assert.assertTrue(searchResponse.isExists());
		assertAccessCodesMatch(searchResponse.getSourceAsMap(), "access_codes", new Integer[] { 1337, 42 });

		// user has 1337 and 42, document has 42 and 1337
		searchResponse = executeGet("tlqdocuments", "3", "tlq_1337_42", "password");
		Assert.assertTrue(searchResponse != null);
		Assert.assertTrue(searchResponse.isExists());
		assertAccessCodesMatch(searchResponse.getSourceAsMap(), "access_codes", new Integer[] { 1337, 42 });

		// user has 1337 and 42, document has no access codes, not visible
		searchResponse = executeGet("tlqdocuments", "16", "tlq_1337_42", "password");
		Assert.assertFalse(searchResponse.isExists());

		// user has 1337 and 42, document has 12345, not visible
		searchResponse = executeGet("tlqdocuments", "17", "tlq_1337_42", "password");
		Assert.assertFalse(searchResponse.isExists());

		// user has 1337 and 42, document has 12345 and 6789, not visible
		searchResponse = executeGet("tlqdocuments", "18", "tlq_1337_42", "password");
		Assert.assertFalse(searchResponse.isExists());

	}

	@Test
	public void testGet_TlqDummyIndex_1337() throws Exception {

		setup(new DynamicSecurityConfig().setConfig("securityconfig_tlq.yml")
				.setSecurityInternalUsers("internal_users_tlq.yml").setSecurityRoles("roles_tlq.yml")
				.setSecurityRolesMapping("roles_mapping_tlq.yml"));

		// no restrictions on this index
		GetResponse searchResponse = executeGet("tlqdummy", "101", "tlq_1337", "password");
		Assert.assertTrue(searchResponse != null);
		Assert.assertTrue(searchResponse.isExists());

		searchResponse = executeGet("tlqdummy", "102", "tlq_1337", "password");
		Assert.assertTrue(searchResponse != null);
		Assert.assertTrue(searchResponse.isExists());

	}

	@Test
	public void testGet_UserAccessCodesIndex_1337() throws Exception {

		setup(new DynamicSecurityConfig().setConfig("securityconfig_tlq.yml")
				.setSecurityInternalUsers("internal_users_tlq.yml").setSecurityRoles("roles_tlq.yml")
				.setSecurityRolesMapping("roles_mapping_tlq.yml"));

		// we expect a security exception here, user has no direct access to
		// user_access_codes index
		HttpResponse response = rh.executeGetRequest("/user_access_codes/_doc/tlq_1337",
				encodeBasicHeader("tlq_1337", "password"));
		Assert.assertEquals(403, response.getStatusCode());
	}

	@Test
	public void testMGet_1337() throws Exception {

		setup(new DynamicSecurityConfig().setConfig("securityconfig_tlq.yml")
				.setSecurityInternalUsers("internal_users_tlq.yml").setSecurityRoles("roles_tlq.yml")
				.setSecurityRolesMapping("roles_mapping_tlq.yml"));

		Map<String, String> indicesAndIds = new HashMap<>();
		indicesAndIds.put("tlqdocuments", "1");
		indicesAndIds.put("tlqdocuments", "2");
		indicesAndIds.put("tlqdocuments", "3");
		indicesAndIds.put("tlqdocuments", "16");
		indicesAndIds.put("tlqdocuments", "17");
		indicesAndIds.put("tlqdocuments", "18");
		indicesAndIds.put("tlqdummy", "101");
		indicesAndIds.put("user_access_codes", "tlq_1337");

		MultiGetResponse searchResponse = executeMGet("tlq_1337", "password", indicesAndIds);

		for (MultiGetItemResponse response : searchResponse.getResponses()) {
			// no response from index "user_access_codes"
			Assert.assertFalse(response.getIndex().equals("user_access_codes"));
			switch (response.getIndex()) {
			case "tlqdocuments":
				Assert.assertTrue(response.getId(), response.getId().equals("1") | response.getId().equals("3"));
				break;
			case "tlqdummy":
				Assert.assertTrue(response.getId(), response.getId().equals("101"));
				break;
			default:
				Assert.fail("Index " + response.getIndex() + " present in mget response, but should not");
			}
		}
	}

// ------------------------
// Test aggregations
// ------------------------

	@Test
	public void testSimpleAggregation_tlqdocuments_AccessCode_1337() throws Exception {

		setup(new DynamicSecurityConfig().setConfig("securityconfig_tlq.yml")
				.setSecurityInternalUsers("internal_users_tlq.yml").setSecurityRoles("roles_tlq.yml")
				.setSecurityRolesMapping("roles_mapping_tlq.yml"));
		
		String body = ""
				+ "		{\n"
				+ "		  \"aggs\": {\n"
				+ "		    \"buaggregation\": {\n"
				+ "		      \"terms\": {\n"
				+ "		        \"field\": \"bu\"\n"
				+ "		      }\n"
				+ "		    }\n"
				+ "		  }\n"
				+ "		}\n"
				+ "";

		// need to add typed_keys so aggregations can be parsed
		// see for example:
		// https://stackoverflow.com/questions/49798654/how-do-you-convert-an-elasticsearch-json-string-response-with-an-aggregation-t
		HttpResponse response = rh.executePostRequest("/tlqdocuments/_search?pretty&typed_keys", body,
				encodeBasicHeader("tlq_1337", "password"));
		Assert.assertTrue(response.getStatusCode() == 200);
		NamedXContentRegistry registry = new NamedXContentRegistry(getDefaultNamedXContents());
		XContentParser xcp = XContentType.JSON.xContent().createParser(registry, LoggingDeprecationHandler.INSTANCE,
				response.getBody());
		SearchResponse searchResponse = SearchResponse.fromXContent(xcp);

		Aggregations aggs = searchResponse.getAggregations();
		Assert.assertNotNull(searchResponse.toString(), aggs);
		Terms agg = aggs.get("buaggregation");
		Assert.assertTrue("Expected aggregation with name 'buaggregation'", agg != null);
		// expect AAA - EEE (FFF does not match) with 2 docs each
		for (String bucketName : new String[] { "AAA", "BBB", "CCC", "DDD", "EEE" }) {
			Bucket bucket = agg.getBucketByKey(bucketName);
			Assert.assertNotNull("Expected bucket " + bucketName + " to be present in agregations", bucket);
			Assert.assertTrue("Expected doc count in bucket " + bucketName + " to be 2", bucket.getDocCount() == 2);
		}
		// expect FFF to be absent
		Assert.assertNull("Expected bucket FFF to be absent", agg.getBucketByKey("FFF"));		
	}


	public static List<NamedXContentRegistry.Entry> getDefaultNamedXContents() {
	    Map<String, ContextParser<Object, ? extends Aggregation>> map = new HashMap<>();
	    map.put(TopHitsAggregationBuilder.NAME, (p, c) -> ParsedTopHits.fromXContent(p, (String) c));
	    map.put(StringTerms.NAME, (p, c) -> ParsedStringTerms.fromXContent(p, (String) c));
	    List<NamedXContentRegistry.Entry> entries = map.entrySet().stream()
	            .map(entry -> new NamedXContentRegistry.Entry(Aggregation.class, new ParseField(entry.getKey()), entry.getValue()))
	            .collect(Collectors.toList());
	  return entries;
	}
}
