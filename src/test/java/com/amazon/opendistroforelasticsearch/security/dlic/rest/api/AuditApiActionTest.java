package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditTestUtils;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.Audit;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import org.apache.http.HttpStatus;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class AuditApiActionTest extends AbstractRestApiUnitTest {

    private static final String ENDPOINT = "/_opendistro/_security/api/audit";
    private static final String CONFIG_ENDPOINT = "/_opendistro/_security/api/audit/config";

    @Test
    public void testAuditConfigApiRead() throws Exception {

        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        RestHelper.HttpResponse response = rh.executeGetRequest(ENDPOINT);
        // default audit.yml defined in test/resources/restapi
        assertEquals("{\"config\":{\"enable_rest\":false," +
                "\"disabled_rest_categories\":[],\"enable_transport\":false," +
                "\"disabled_transport_categories\":[]," +
                "\"internal_config\":true,\"external_config\":false," +
                "\"resolve_bulk_requests\":false,\"log_request_body\":false,\"resolve_indices\":false,\"exclude_sensitive_headers\":false," +
                "\"ignore_users\":[\"kibanaserver\"],\"ignore_requests\":[]," +
                "\"immutable_indices\":[]," +
                "\"read_metadata_only\":false,\"read_watched_fields\":[],\"read_ignore_users\":[]," +
                "\"write_metadata_only\":false,\"write_log_diffs\":false,\"write_watched_indices\":[],\"write_ignore_users\":[]," +
                "\"salt\":\"e1ukloTsQlOgPquJ\"}}", response.getBody());
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // should have /config for put request
        response = rh.executePutRequest(ENDPOINT, "{\"xxx\": 1}");
        assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

        // no post supported
        response = rh.executePostRequest(ENDPOINT, "{\"xxx\": 1}");
        assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());

        // should have /config for patch request
        response = rh.executePatchRequest(ENDPOINT, "{\"xxx\": 1}");
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // no delete supported
        response = rh.executeDeleteRequest(ENDPOINT);
        assertEquals(HttpStatus.SC_METHOD_NOT_ALLOWED, response.getStatusCode());
    }

    @Test
    public void testAuditConfigApiWrite() throws Exception {
        setup();

        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        // valid request
        Audit audit = new Audit();
        RestHelper.HttpResponse response = rh.executePutRequest(CONFIG_ENDPOINT, AuditTestUtils.createAuditPayload(audit));
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // bad salt
        audit = new Audit();
        audit.setSalt("abcd");
        response = rh.executePutRequest(CONFIG_ENDPOINT, AuditTestUtils.createAuditPayload(audit));
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // valid rest category
        response = rh.executePatchRequest(ENDPOINT, "[{\"op\": \"replace\",\"path\": \"/config/disabled_rest_categories\",\"value\": [\"AUTHENTICATED\"]}]");
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // bad rest category
        response = rh.executePatchRequest(ENDPOINT, "[{\"op\": \"replace\",\"path\": \"/config/disabled_rest_categories\",\"value\": [\"testing\"]}]");
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // valid transport category
        response = rh.executePatchRequest(ENDPOINT, "[{\"op\": \"replace\",\"path\": \"/config/disabled_rest_categories\",\"value\": [\"SSL_EXCEPTION\"]}]");
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // bad transport category
        response = rh.executePatchRequest(ENDPOINT, "[{\"op\": \"replace\",\"path\": \"/config/disabled_transport_categories\",\"value\": [\"testing\"]}]");
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // bad payload
        response = rh.executePutRequest(CONFIG_ENDPOINT, "{\"test\": true}");
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());

        // patch request
        response = rh.executePatchRequest(ENDPOINT, "[{\"op\": \"replace\",\"path\": \"/config/enable_rest\",\"value\": \"true\"}]");
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        // bad patch request
        response = rh.executePatchRequest(ENDPOINT, "[{\"op\": \"replace\",\"path\": \"/config/testing\",\"value\": \"true\"}]");
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
    }
}
