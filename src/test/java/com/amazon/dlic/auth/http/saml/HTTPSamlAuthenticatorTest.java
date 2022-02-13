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

package com.amazon.dlic.auth.http.saml;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.KeyManagerFactory;

import org.opensearch.security.DefaultObjectMapper;
import org.apache.cxf.rs.security.jose.jws.JwsJwtCompactConsumer;
import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.opensearch.common.bytes.BytesArray;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.RestStatus;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opensaml.saml.saml2.core.NameIDType;

import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.user.AuthCredentials;
import org.opensearch.security.util.FakeRestRequest;
import com.fasterxml.jackson.core.type.TypeReference;
import com.google.common.collect.ImmutableMap;

import static com.amazon.dlic.auth.http.saml.HTTPSamlAuthenticator.IDP_METADATA_CONTENT;
import static com.amazon.dlic.auth.http.saml.HTTPSamlAuthenticator.IDP_METADATA_URL;

public class HTTPSamlAuthenticatorTest {
    protected MockSamlIdpServer mockSamlIdpServer;
    private static final Pattern WWW_AUTHENTICATE_PATTERN = Pattern
            .compile("([^\\s]+)\\s*([^\\s=]+)=\"([^\"]+)\"\\s*([^\\s=]+)=\"([^\"]+)\"\\s*([^\\s=]+)=\"([^\"]+)\"\\s*");

    private static final String SPOCK_KEY = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
            + "MIIE6TAbBgkqhkiG9w0BBQMwDgQI0JMa7PyPedwCAggABIIEyLdPL2RXj8jjKqFT\n"
            + "p+7vywwyxyUQOQvvIIU6H+lKZPd/y6pxzYtGd1suT2aermrrlh4b/ZXXfj/EcKcw\n"
            + "GgcXB60Kr7UHIv7Xr498S4EKa9R7UG0NtWtsA3FVR5ndwXI+CiRSShhkskmpseVH\n"
            + "dNWAoUsKQFbZRLnoINMKIw1/lpQBUwAUcYVB7LxLeKSTVHn/h9kvq0tad1kbE5OY\n"
            + "GnOLEVW311++XQ3Ep/13tGEZCrxef+QsnmXuYxXBq4RvbyGZOvyM2FC7va8KzJxl\n"
            + "P38SPEL1TzqokQB/eLDBMBOCqkhTbP/8lNuoEVm44T6//ijBp6VdBB+YRIFh3NrS\n"
            + "1fPuDVgHr1jrRGICe8lzWy/bSa+4FlxYjn5qpEzZQtbC6C+iRzlwtlCiDdKl8zJ1\n"
            + "YF80OW9Gr3Kvph2LJukBiODcyWUAsAf5vJH3vfPV4T9kWTNMu2NCy3Ch8u9d906k\n"
            + "zojB/tRRdZ/XCftkU05gYU/5ruU1YA49U60s0KWXvSLmecFo2SjkcEoPDI+Y80Uw\n"
            + "OB/5kdh1M1uu/qjoJTPWBbZ28L6e0fiMsr7eWSG7PQFwnN6VzY6Oesm8AS8LMe3V\n"
            + "Dr4Syec8vVfGg/EDsjNC1yeZTzlO66NQYGkpnHwK1kgX/XXe7fjDfztPyM9crBXj\n"
            + "YcYpNULAkMj9QUVDQqQ7L8TjoAFQiSdvNa+kkDhaxnAXoxfqeacTtkpKcHADsAQL\n"
            + "azfoyflnpuZ1dIn0noRFsVuguKDp4k990bhXu9RkQ1H5IzIoYqJwypacVdt3m74o\n"
            + "jpZvBY6z0EtBNkze6WA0Vj0BSWpy/IzndDwroG4Xf+54hn0R/Tp5K5UNttOaJN8c\n"
            + "9U/NTiGJTJg1O4x6xbPD7C5bBdoJ/MH5yJuk/dUc7pVkisLpuH9sAPETjYCdFIjX\n"
            + "MSRJCtq2ouT0ZRW1yBIrKIadgHLExhjZjTSQCBXJMbO7r2DjPHMZU23GTiPtC8ua\n"
            + "L2BmC+AW7RQ2Fyo3hJDT2TM4XlMMlTtGuFxkWwmjV+FiwfjbiR3cp0+99/X6OFu5\n"
            + "ysgZLuTMQsmWNJ8ZARZqBnkGnN92Aw4D5GLCFv3QXO+fqJnOP1PbkPwpjq59Yytf\n"
            + "U4XqyTwRYSXRzwPFFb7RcgL9HbmjpRBEnvqEjKYeXxkBnhs+WOWN/PuJzGgP5uAk\n"
            + "jAjQbtgLEPd4WpGcwEhkX6S1DBi8NrGapuehCjXsN1axify8Kx4eRuTiPdINlgsq\n"
            + "d2MsPIuDgU2+0QXrXjRLwABcMGuKcmmfZjC+zZomj+yr4+Togs3vhSj9yGK3HHMh\n"
            + "NgOlPBTibruXXa4AI07c28j3sEry+CMZrUGyYg6o1HLBpBfOmp7V5HJcvkMFWCVy\n"
            + "DPFm5LZu0jZMDj9a+oGkv4hfp1xSXSUjhjiGz47xFJb6PH9pOUIkhTEdFCgEXbaR\n"
            + "fXcR+kakLOotL4X1cT9cpxdimN3CCTBpr03gCv2NCVYMYhHKHK+CQVngJrY+PzMH\n"
            + "q6fw81bUNcixZyeXFfLFN6GK75k51UV7YS/X2H8YkqGeIVNaFjrcqUoVAN8jQOeb\n"
            + "XXIa8gT/MdNT0+W3NHKcbE31pDhOI92COZWlhOyp1cLhyo1ytayjxPTl/2RM/Vtj\n" + "T9IKkp7810LOKhrCDQ==\n"
            + "-----END ENCRYPTED PRIVATE KEY-----";

    private static X509Certificate spSigningCertificate;
    private static PrivateKey spSigningPrivateKey;

    @Before
    public void setUp() throws Exception {
        mockSamlIdpServer = new MockSamlIdpServer();
        mockSamlIdpServer.start();
    }

    @After
    public void tearDown() {
        if (mockSamlIdpServer != null) {
            try {
                mockSamlIdpServer.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    @Test
    public void basicTest() throws Exception {
        mockSamlIdpServer.setSignResponses(true);
        mockSamlIdpServer.loadSigningKeys("saml/kirk-keystore.jks", "kirk");
        mockSamlIdpServer.setAuthenticateUser("horst");
        mockSamlIdpServer.setEndpointQueryString(null);

        Settings settings = Settings.builder().put(IDP_METADATA_URL, mockSamlIdpServer.getMetadataUri())
                .put("kibana_url", "http://wherever").put("idp.entity_id", mockSamlIdpServer.getIdpEntityId())
                .put("exchange_key", "abc").put("roles_key", "roles").put("path.home", ".").build();

        HTTPSamlAuthenticator samlAuthenticator = new HTTPSamlAuthenticator(settings, null);

        AuthenticateHeaders authenticateHeaders = getAutenticateHeaders(samlAuthenticator);

        String encodedSamlResponse = mockSamlIdpServer.handleSsoGetRequestURI(authenticateHeaders.location);

        RestRequest tokenRestRequest = buildTokenExchangeRestRequest(encodedSamlResponse, authenticateHeaders);
        TestRestChannel tokenRestChannel = new TestRestChannel(tokenRestRequest);

        samlAuthenticator.reRequestAuthentication(tokenRestChannel, null);

        String responseJson = new String(BytesReference.toBytes(tokenRestChannel.response.content()));
        HashMap<String, Object> response = DefaultObjectMapper.objectMapper.readValue(responseJson,
                new TypeReference<HashMap<String, Object>>() {
                });
        String authorization = (String) response.get("authorization");

        Assert.assertNotNull("Expected authorization attribute in JSON: " + responseJson, authorization);

        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(authorization.replaceAll("\\s*bearer\\s*", ""));
        JwtToken jwt = jwtConsumer.getJwtToken();

        Assert.assertEquals("horst", jwt.getClaim("sub"));
    }

    @Test
    public void decryptAssertionsTest() throws Exception {
        mockSamlIdpServer.setAuthenticateUser("horst");
        mockSamlIdpServer.setEndpointQueryString(null);
        mockSamlIdpServer.setSpSignatureCertificate(spSigningCertificate);
        mockSamlIdpServer.setEncryptAssertion(true);

        Settings settings = Settings.builder().put(IDP_METADATA_URL, mockSamlIdpServer.getMetadataUri())
                .put("kibana_url", "http://wherever").put("idp.entity_id", mockSamlIdpServer.getIdpEntityId())
                .put("sp.signature_private_key", "-BEGIN PRIVATE KEY-\n"
                        + Base64.getEncoder().encodeToString(spSigningPrivateKey.getEncoded()) + "-END PRIVATE KEY-")
                .put("exchange_key", "abc").put("roles_key", "roles").put("path.home", ".").build();

        HTTPSamlAuthenticator samlAuthenticator = new HTTPSamlAuthenticator(settings, null);

        AuthenticateHeaders authenticateHeaders = getAutenticateHeaders(samlAuthenticator);

        String encodedSamlResponse = mockSamlIdpServer.handleSsoGetRequestURI(authenticateHeaders.location);

        RestRequest tokenRestRequest = buildTokenExchangeRestRequest(encodedSamlResponse, authenticateHeaders);
        TestRestChannel tokenRestChannel = new TestRestChannel(tokenRestRequest);

        samlAuthenticator.reRequestAuthentication(tokenRestChannel, null);

        String responseJson = new String(BytesReference.toBytes(tokenRestChannel.response.content()));
        HashMap<String, Object> response = DefaultObjectMapper.objectMapper.readValue(responseJson,
                new TypeReference<HashMap<String, Object>>() {
                });
        String authorization = (String) response.get("authorization");

        Assert.assertNotNull("Expected authorization attribute in JSON: " + responseJson, authorization);

        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(authorization.replaceAll("\\s*bearer\\s*", ""));
        JwtToken jwt = jwtConsumer.getJwtToken();

        Assert.assertEquals("horst", jwt.getClaim("sub"));
    }

    @Test
    public void shouldUnescapeSamlEntitiesTest() throws Exception {
        mockSamlIdpServer.setAuthenticateUser("ABC\\User1");
        mockSamlIdpServer.setEndpointQueryString(null);
        mockSamlIdpServer.setSpSignatureCertificate(spSigningCertificate);
        mockSamlIdpServer.setEncryptAssertion(true);
        mockSamlIdpServer.setAuthenticateUserRoles(Arrays.asList("ABC\\Admin"));

        Settings settings = Settings.builder().put(IDP_METADATA_URL, mockSamlIdpServer.getMetadataUri())
                .put("kibana_url", "http://wherever").put("idp.entity_id", mockSamlIdpServer.getIdpEntityId())
                .put("sp.signature_private_key", "-BEGIN PRIVATE KEY-\n"
                        + Base64.getEncoder().encodeToString(spSigningPrivateKey.getEncoded()) + "-END PRIVATE KEY-")
                .put("exchange_key", "abc").put("roles_key", "roles").put("path.home", ".").build();

        HTTPSamlAuthenticator samlAuthenticator = new HTTPSamlAuthenticator(settings, null);

        AuthenticateHeaders authenticateHeaders = getAutenticateHeaders(samlAuthenticator);

        String encodedSamlResponse = mockSamlIdpServer.handleSsoGetRequestURI(authenticateHeaders.location);

        RestRequest tokenRestRequest = buildTokenExchangeRestRequest(encodedSamlResponse, authenticateHeaders);
        TestRestChannel tokenRestChannel = new TestRestChannel(tokenRestRequest);

        samlAuthenticator.reRequestAuthentication(tokenRestChannel, null);

        String responseJson = new String(BytesReference.toBytes(tokenRestChannel.response.content()));
        HashMap<String, Object> response = DefaultObjectMapper.objectMapper.readValue(responseJson,
                new TypeReference<HashMap<String, Object>>() {
                });
        String authorization = (String) response.get("authorization");

        Assert.assertNotNull("Expected authorization attribute in JSON: " + responseJson, authorization);

        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(authorization.replaceAll("\\s*bearer\\s*", ""));
        JwtToken jwt = jwtConsumer.getJwtToken();

        Assert.assertEquals("ABC\\User1", jwt.getClaim("sub"));
        Assert.assertEquals("ABC\\User1",  samlAuthenticator.httpJwtAuthenticator.extractSubject(jwt.getClaims()));
        Assert.assertEquals("[ABC\\Admin]", String.valueOf(jwt.getClaim("roles")));
        Assert.assertEquals("ABC\\Admin", samlAuthenticator.httpJwtAuthenticator.extractRoles(jwt.getClaims())[0]);
    }

    @Test
    public void shouldUnescapeSamlEntitiesTest2() throws Exception {
        mockSamlIdpServer.setAuthenticateUser("ABC\"User1");
        mockSamlIdpServer.setEndpointQueryString(null);
        mockSamlIdpServer.setSpSignatureCertificate(spSigningCertificate);
        mockSamlIdpServer.setEncryptAssertion(true);
        mockSamlIdpServer.setAuthenticateUserRoles(Arrays.asList("ABC\"Admin"));

        Settings settings = Settings.builder().put(IDP_METADATA_URL, mockSamlIdpServer.getMetadataUri())
                .put("kibana_url", "http://wherever").put("idp.entity_id", mockSamlIdpServer.getIdpEntityId())
                .put("sp.signature_private_key", "-BEGIN PRIVATE KEY-\n"
                        + Base64.getEncoder().encodeToString(spSigningPrivateKey.getEncoded()) + "-END PRIVATE KEY-")
                .put("exchange_key", "abc").put("roles_key", "roles").put("path.home", ".").build();

        HTTPSamlAuthenticator samlAuthenticator = new HTTPSamlAuthenticator(settings, null);

        AuthenticateHeaders authenticateHeaders = getAutenticateHeaders(samlAuthenticator);

        String encodedSamlResponse = mockSamlIdpServer.handleSsoGetRequestURI(authenticateHeaders.location);

        RestRequest tokenRestRequest = buildTokenExchangeRestRequest(encodedSamlResponse, authenticateHeaders);
        TestRestChannel tokenRestChannel = new TestRestChannel(tokenRestRequest);

        samlAuthenticator.reRequestAuthentication(tokenRestChannel, null);

        String responseJson = new String(BytesReference.toBytes(tokenRestChannel.response.content()));
        HashMap<String, Object> response = DefaultObjectMapper.objectMapper.readValue(responseJson,
                new TypeReference<HashMap<String, Object>>() {
                });
        String authorization = (String) response.get("authorization");

        Assert.assertNotNull("Expected authorization attribute in JSON: " + responseJson, authorization);

        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(authorization.replaceAll("\\s*bearer\\s*", ""));
        JwtToken jwt = jwtConsumer.getJwtToken();

        Assert.assertEquals("ABC\"User1", jwt.getClaim("sub"));
        Assert.assertEquals("ABC\"User1",  samlAuthenticator.httpJwtAuthenticator.extractSubject(jwt.getClaims()));
        Assert.assertEquals("[ABC\"Admin]", String.valueOf(jwt.getClaim("roles")));
        Assert.assertEquals("ABC\"Admin", samlAuthenticator.httpJwtAuthenticator.extractRoles(jwt.getClaims())[0]);
    }

    @Test
    public void shouldNotEscapeSamlEntities() throws Exception {
        mockSamlIdpServer.setAuthenticateUser("ABC/User1");
        mockSamlIdpServer.setEndpointQueryString(null);
        mockSamlIdpServer.setSpSignatureCertificate(spSigningCertificate);
        mockSamlIdpServer.setEncryptAssertion(true);
        mockSamlIdpServer.setAuthenticateUserRoles(Arrays.asList("ABC/Admin"));

        Settings settings = Settings.builder().put(IDP_METADATA_URL, mockSamlIdpServer.getMetadataUri())
                .put("kibana_url", "http://wherever").put("idp.entity_id", mockSamlIdpServer.getIdpEntityId())
                .put("sp.signature_private_key", "-BEGIN PRIVATE KEY-\n"
                        + Base64.getEncoder().encodeToString(spSigningPrivateKey.getEncoded()) + "-END PRIVATE KEY-")
                .put("exchange_key", "abc").put("roles_key", "roles").put("path.home", ".").build();

        HTTPSamlAuthenticator samlAuthenticator = new HTTPSamlAuthenticator(settings, null);

        AuthenticateHeaders authenticateHeaders = getAutenticateHeaders(samlAuthenticator);

        String encodedSamlResponse = mockSamlIdpServer.handleSsoGetRequestURI(authenticateHeaders.location);

        RestRequest tokenRestRequest = buildTokenExchangeRestRequest(encodedSamlResponse, authenticateHeaders);
        TestRestChannel tokenRestChannel = new TestRestChannel(tokenRestRequest);

        samlAuthenticator.reRequestAuthentication(tokenRestChannel, null);

        String responseJson = new String(BytesReference.toBytes(tokenRestChannel.response.content()));
        HashMap<String, Object> response = DefaultObjectMapper.objectMapper.readValue(responseJson,
                new TypeReference<HashMap<String, Object>>() {
                });
        String authorization = (String) response.get("authorization");

        Assert.assertNotNull("Expected authorization attribute in JSON: " + responseJson, authorization);

        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(authorization.replaceAll("\\s*bearer\\s*", ""));
        JwtToken jwt = jwtConsumer.getJwtToken();

        Assert.assertEquals("ABC/User1", jwt.getClaim("sub"));
        Assert.assertEquals("ABC/User1",  samlAuthenticator.httpJwtAuthenticator.extractSubject(jwt.getClaims()));
        Assert.assertEquals("[ABC/Admin]", String.valueOf(jwt.getClaim("roles")));
        Assert.assertEquals("ABC/Admin", samlAuthenticator.httpJwtAuthenticator.extractRoles(jwt.getClaims())[0]);
    }

    @Test
    public void testMetadataBody() throws Exception {
        mockSamlIdpServer.setSignResponses(true);
        mockSamlIdpServer.loadSigningKeys("saml/kirk-keystore.jks", "kirk");
        mockSamlIdpServer.setAuthenticateUser("horst");
        mockSamlIdpServer.setEndpointQueryString(null);

        // Note: We need to replace endpoint with mockSamlIdpServer endpoint
        final String metadataBody = FileHelper.loadFile("saml/metadata.xml")
                                        .replaceAll("http://localhost:33667/", mockSamlIdpServer.getMetadataUri());

        Settings settings = Settings.builder().put(IDP_METADATA_CONTENT, metadataBody)
            .put("kibana_url", "http://wherever")
            .put("idp.entity_id", mockSamlIdpServer.getIdpEntityId())
            .put("exchange_key", "abc").put("roles_key", "roles").put("path.home", ".").build();

        HTTPSamlAuthenticator samlAuthenticator = new HTTPSamlAuthenticator(settings, null);

        AuthenticateHeaders authenticateHeaders = getAutenticateHeaders(samlAuthenticator);

        String encodedSamlResponse = mockSamlIdpServer.handleSsoGetRequestURI(authenticateHeaders.location);

        RestRequest tokenRestRequest = buildTokenExchangeRestRequest(encodedSamlResponse, authenticateHeaders);
        TestRestChannel tokenRestChannel = new TestRestChannel(tokenRestRequest);

        samlAuthenticator.reRequestAuthentication(tokenRestChannel, null);

        String responseJson = new String(BytesReference.toBytes(tokenRestChannel.response.content()));
        HashMap<String, Object> response = DefaultObjectMapper.objectMapper.readValue(responseJson,
            new TypeReference<HashMap<String, Object>>() {
            });
        String authorization = (String) response.get("authorization");

        Assert.assertNotNull("Expected authorization attribute in JSON: " + responseJson, authorization);

        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(authorization.replaceAll("\\s*bearer\\s*", ""));
        JwtToken jwt = jwtConsumer.getJwtToken();

        Assert.assertEquals("horst", jwt.getClaim("sub"));
    }


    @Test(expected= RuntimeException.class)
    public void testEmptyMetadataBody() throws Exception {
        mockSamlIdpServer.setSignResponses(true);
        mockSamlIdpServer.loadSigningKeys("saml/kirk-keystore.jks", "kirk");
        mockSamlIdpServer.setAuthenticateUser("horst");
        mockSamlIdpServer.setEndpointQueryString(null);

        Settings settings = Settings.builder().put(IDP_METADATA_CONTENT, "")
            .put("kibana_url", "http://wherever")
            .put("idp.entity_id", mockSamlIdpServer.getIdpEntityId())
            .put("exchange_key", "abc").put("roles_key", "roles").put("path.home", ".").build();

        new HTTPSamlAuthenticator(settings, null);
    }

    @Test
    public void unsolicitedSsoTest() throws Exception {
        mockSamlIdpServer.setSignResponses(true);
        mockSamlIdpServer.loadSigningKeys("saml/kirk-keystore.jks", "kirk");
        mockSamlIdpServer.setAuthenticateUser("horst");
        mockSamlIdpServer.setEndpointQueryString(null);
        mockSamlIdpServer.setDefaultAssertionConsumerService("http://wherever/opendistrosecurity/saml/acs/idpinitiated");

        Settings settings = Settings.builder().put(IDP_METADATA_URL, mockSamlIdpServer.getMetadataUri())
                .put("kibana_url", "http://wherever").put("idp.entity_id", mockSamlIdpServer.getIdpEntityId())
                .put("exchange_key", "abc").put("roles_key", "roles").put("path.home", ".").build();

        HTTPSamlAuthenticator samlAuthenticator = new HTTPSamlAuthenticator(settings, null);

        String encodedSamlResponse = mockSamlIdpServer.createUnsolicitedSamlResponse();

        RestRequest tokenRestRequest = buildTokenExchangeRestRequest(encodedSamlResponse, null,
                "/opendistrosecurity/saml/acs/idpinitiated");
        TestRestChannel tokenRestChannel = new TestRestChannel(tokenRestRequest);

        samlAuthenticator.reRequestAuthentication(tokenRestChannel, null);

        String responseJson = new String(BytesReference.toBytes(tokenRestChannel.response.content()));
        HashMap<String, Object> response = DefaultObjectMapper.objectMapper.readValue(responseJson,
                new TypeReference<HashMap<String, Object>>() {
                });
        String authorization = (String) response.get("authorization");

        Assert.assertNotNull("Expected authorization attribute in JSON: " + responseJson, authorization);

        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(authorization.replaceAll("\\s*bearer\\s*", ""));
        JwtToken jwt = jwtConsumer.getJwtToken();

        Assert.assertEquals("horst", jwt.getClaim("sub"));
    }

    @Test
    public void badUnsolicitedSsoTest() throws Exception {
        mockSamlIdpServer.setSignResponses(true);
        mockSamlIdpServer.loadSigningKeys("saml/kirk-keystore.jks", "kirk");
        mockSamlIdpServer.setAuthenticateUser("horst");
        mockSamlIdpServer.setEndpointQueryString(null);
        mockSamlIdpServer.setDefaultAssertionConsumerService("http://wherever/opendistrosecurity/saml/acs/idpinitiated");

        Settings settings = Settings.builder().put(IDP_METADATA_URL, mockSamlIdpServer.getMetadataUri())
                .put("kibana_url", "http://wherever").put("idp.entity_id", mockSamlIdpServer.getIdpEntityId())
                .put("exchange_key", "abc").put("roles_key", "roles").put("path.home", ".").build();

        HTTPSamlAuthenticator samlAuthenticator = new HTTPSamlAuthenticator(settings, null);

        String encodedSamlResponse = mockSamlIdpServer.createUnsolicitedSamlResponse();

        AuthenticateHeaders authenticateHeaders = new AuthenticateHeaders("http://wherever/opendistrosecurity/saml/acs/",
                "wrong_request_id");

        RestRequest tokenRestRequest = buildTokenExchangeRestRequest(encodedSamlResponse, authenticateHeaders,
                "/opendistrosecurity/saml/acs/idpinitiated");
        TestRestChannel tokenRestChannel = new TestRestChannel(tokenRestRequest);

        samlAuthenticator.reRequestAuthentication(tokenRestChannel, null);

        Assert.assertEquals(RestStatus.UNAUTHORIZED, tokenRestChannel.response.status());
    }

    @Test
    public void wrongCertTest() throws Exception {
        mockSamlIdpServer.setSignResponses(true);
        mockSamlIdpServer.loadSigningKeys("saml/kirk-keystore.jks", "kirk");
        mockSamlIdpServer.setAuthenticateUser("horst");
        mockSamlIdpServer.setEndpointQueryString(null);

        Settings settings = Settings.builder().put(IDP_METADATA_URL, mockSamlIdpServer.getMetadataUri())
                .put("kibana_url", "http://wherever").put("idp.entity_id", mockSamlIdpServer.getIdpEntityId())
                .put("exchange_key", "abc").put("roles_key", "roles").put("path.home", ".").build();

        HTTPSamlAuthenticator samlAuthenticator = new HTTPSamlAuthenticator(settings, null);

        AuthenticateHeaders authenticateHeaders = getAutenticateHeaders(samlAuthenticator);

        mockSamlIdpServer.loadSigningKeys("saml/spock-keystore.jks", "spock");

        String encodedSamlResponse = mockSamlIdpServer.handleSsoGetRequestURI(authenticateHeaders.location);

        RestRequest tokenRestRequest = buildTokenExchangeRestRequest(encodedSamlResponse, authenticateHeaders);
        TestRestChannel tokenRestChannel = new TestRestChannel(tokenRestRequest);

        samlAuthenticator.reRequestAuthentication(tokenRestChannel, null);

        Assert.assertEquals(401, tokenRestChannel.response.status().getStatus());
    }

    @Test
    public void noSignatureTest() throws Exception {
        mockSamlIdpServer.setSignResponses(false);
        mockSamlIdpServer.setAuthenticateUser("horst");
        mockSamlIdpServer.setEndpointQueryString(null);

        Settings settings = Settings.builder().put(IDP_METADATA_URL, mockSamlIdpServer.getMetadataUri())
                .put("kibana_url", "http://wherever").put("idp.entity_id", mockSamlIdpServer.getIdpEntityId())
                .put("exchange_key", "abc").put("roles_key", "roles").put("path.home", ".").build();

        HTTPSamlAuthenticator samlAuthenticator = new HTTPSamlAuthenticator(settings, null);

        AuthenticateHeaders authenticateHeaders = getAutenticateHeaders(samlAuthenticator);

        String encodedSamlResponse = mockSamlIdpServer.handleSsoGetRequestURI(authenticateHeaders.location);

        RestRequest tokenRestRequest = buildTokenExchangeRestRequest(encodedSamlResponse, authenticateHeaders);
        TestRestChannel tokenRestChannel = new TestRestChannel(tokenRestRequest);

        samlAuthenticator.reRequestAuthentication(tokenRestChannel, null);

        Assert.assertEquals(401, tokenRestChannel.response.status().getStatus());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void rolesTest() throws Exception {
        mockSamlIdpServer.setSignResponses(true);
        mockSamlIdpServer.loadSigningKeys("saml/kirk-keystore.jks", "kirk");
        mockSamlIdpServer.setAuthenticateUser("horst");
        mockSamlIdpServer.setAuthenticateUserRoles(Arrays.asList("a ,c", "b   ,d,   e", "f", "g,,h, ,i"));
        mockSamlIdpServer.setEndpointQueryString(null);

        Settings settings = Settings.builder().put(IDP_METADATA_URL, mockSamlIdpServer.getMetadataUri())
                .put("kibana_url", "http://wherever").put("idp.entity_id", mockSamlIdpServer.getIdpEntityId())
                .put("exchange_key", "abc").put("roles_key", "roles").put("path.home", ".").put("roles_seperator", ",").build();

        HTTPSamlAuthenticator samlAuthenticator = new HTTPSamlAuthenticator(settings, null);

        AuthenticateHeaders authenticateHeaders = getAutenticateHeaders(samlAuthenticator);

        String encodedSamlResponse = mockSamlIdpServer.handleSsoGetRequestURI(authenticateHeaders.location);

        RestRequest tokenRestRequest = buildTokenExchangeRestRequest(encodedSamlResponse, authenticateHeaders);
        TestRestChannel tokenRestChannel = new TestRestChannel(tokenRestRequest);

        samlAuthenticator.reRequestAuthentication(tokenRestChannel, null);

        String responseJson = new String(BytesReference.toBytes(tokenRestChannel.response.content()));
        HashMap<String, Object> response = DefaultObjectMapper.objectMapper.readValue(responseJson,
                new TypeReference<HashMap<String, Object>>() {
                });
        String authorization = (String) response.get("authorization");

        Assert.assertNotNull("Expected authorization attribute in JSON: " + responseJson, authorization);

        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(authorization.replaceAll("\\s*bearer\\s*", ""));
        JwtToken jwt = jwtConsumer.getJwtToken();

        Assert.assertEquals("horst", jwt.getClaim("sub"));
        Assert.assertArrayEquals(new String[] { "a ", "c", "b   ", "d", "   e", "f", "g", "h", " ", "i" },
                ((List<String>) jwt.getClaim("roles")).toArray(new String[0]));
    }

    @Test
    public void idpEndpointWithQueryStringTest() throws Exception {
        mockSamlIdpServer.setSignResponses(true);
        mockSamlIdpServer.loadSigningKeys("saml/kirk-keystore.jks", "kirk");
        mockSamlIdpServer.setAuthenticateUser("horst");
        mockSamlIdpServer.setEndpointQueryString("extra=query");

        Settings settings = Settings.builder().put(IDP_METADATA_URL, mockSamlIdpServer.getMetadataUri())
                .put("kibana_url", "http://wherever").put("idp.entity_id", mockSamlIdpServer.getIdpEntityId())
                .put("exchange_key", "abc").put("roles_key", "roles").put("path.home", ".").build();

        HTTPSamlAuthenticator samlAuthenticator = new HTTPSamlAuthenticator(settings, null);

        AuthenticateHeaders authenticateHeaders = getAutenticateHeaders(samlAuthenticator);

        String encodedSamlResponse = mockSamlIdpServer.handleSsoGetRequestURI(authenticateHeaders.location);

        RestRequest tokenRestRequest = buildTokenExchangeRestRequest(encodedSamlResponse, authenticateHeaders);
        TestRestChannel tokenRestChannel = new TestRestChannel(tokenRestRequest);

        samlAuthenticator.reRequestAuthentication(tokenRestChannel, null);

        String responseJson = new String(BytesReference.toBytes(tokenRestChannel.response.content()));
        HashMap<String, Object> response = DefaultObjectMapper.objectMapper.readValue(responseJson,
                new TypeReference<HashMap<String, Object>>() {
                });
        String authorization = (String) response.get("authorization");

        Assert.assertNotNull("Expected authorization attribute in JSON: " + responseJson, authorization);

        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(authorization.replaceAll("\\s*bearer\\s*", ""));
        JwtToken jwt = jwtConsumer.getJwtToken();

        Assert.assertEquals("horst", jwt.getClaim("sub"));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void commaSeparatedRolesTest() throws Exception {
        mockSamlIdpServer.setAuthenticateUser("horst");
        mockSamlIdpServer.setSignResponses(true);
        mockSamlIdpServer.loadSigningKeys("saml/kirk-keystore.jks", "kirk");
        mockSamlIdpServer.setAuthenticateUserRoles(Arrays.asList("a,b"));
        mockSamlIdpServer.setEndpointQueryString(null);

        Settings settings = Settings.builder().put(IDP_METADATA_URL, mockSamlIdpServer.getMetadataUri())
                .put("kibana_url", "http://wherever").put("idp.entity_id", mockSamlIdpServer.getIdpEntityId())
                .put("exchange_key", "abc").put("roles_key", "roles").put("roles_seperator", ",").put("path.home", ".")
                .build();

        HTTPSamlAuthenticator samlAuthenticator = new HTTPSamlAuthenticator(settings, null);

        AuthenticateHeaders authenticateHeaders = getAutenticateHeaders(samlAuthenticator);

        String encodedSamlResponse = mockSamlIdpServer.handleSsoGetRequestURI(authenticateHeaders.location);

        RestRequest tokenRestRequest = buildTokenExchangeRestRequest(encodedSamlResponse, authenticateHeaders);
        TestRestChannel tokenRestChannel = new TestRestChannel(tokenRestRequest);

        samlAuthenticator.reRequestAuthentication(tokenRestChannel, null);

        String responseJson = new String(BytesReference.toBytes(tokenRestChannel.response.content()));
        HashMap<String, Object> response = DefaultObjectMapper.objectMapper.readValue(responseJson,
                new TypeReference<HashMap<String, Object>>() {
                });
        String authorization = (String) response.get("authorization");

        Assert.assertNotNull("Expected authorization attribute in JSON: " + responseJson, authorization);

        JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(authorization.replaceAll("\\s*bearer\\s*", ""));
        JwtToken jwt = jwtConsumer.getJwtToken();

        Assert.assertEquals("horst", jwt.getClaim("sub"));
        Assert.assertArrayEquals(new String[] { "a", "b" },
                ((List<String>) jwt.getClaim("roles")).toArray(new String[0]));
    }

    @Test
    public void basicLogoutTest() throws Exception {
        mockSamlIdpServer.setSignResponses(true);
        mockSamlIdpServer.loadSigningKeys("saml/kirk-keystore.jks", "kirk");
        mockSamlIdpServer.setAuthenticateUser("horst");
        mockSamlIdpServer.setSpSignatureCertificate(spSigningCertificate);
        mockSamlIdpServer.setEndpointQueryString(null);

        Settings settings = Settings.builder().put(IDP_METADATA_URL, mockSamlIdpServer.getMetadataUri())
                .put("kibana_url", "http://wherever").put("idp.entity_id", mockSamlIdpServer.getIdpEntityId())
                .put("exchange_key", "abc").put("roles_key", "roles")
                .put("sp.signature_private_key", "-BEGIN PRIVATE KEY-\n"
                        + Base64.getEncoder().encodeToString(spSigningPrivateKey.getEncoded()) + "-END PRIVATE KEY-")
                .put("path.home", ".").build();

        HTTPSamlAuthenticator samlAuthenticator = new HTTPSamlAuthenticator(settings, null);

        AuthCredentials authCredentials = new AuthCredentials("horst");
        authCredentials.addAttribute("attr.jwt.sub", "horst");
        authCredentials.addAttribute("attr.jwt.saml_nif", NameIDType.UNSPECIFIED);
        authCredentials.addAttribute("attr.jwt.saml_si", "si123");

        String logoutUrl = samlAuthenticator.buildLogoutUrl(authCredentials);

        mockSamlIdpServer.handleSloGetRequestURI(logoutUrl);

    }

    @Test
    public void basicLogoutTestEncryptedKey() throws Exception {
        mockSamlIdpServer.setSignResponses(true);
        mockSamlIdpServer.loadSigningKeys("saml/kirk-keystore.jks", "kirk");
        mockSamlIdpServer.setAuthenticateUser("horst");
        mockSamlIdpServer.setSpSignatureCertificate(spSigningCertificate);
        mockSamlIdpServer.setEndpointQueryString(null);

        Settings settings = Settings.builder().put(IDP_METADATA_URL, mockSamlIdpServer.getMetadataUri())
                .put("kibana_url", "http://wherever").put("idp.entity_id", mockSamlIdpServer.getIdpEntityId())
                .put("exchange_key", "abc").put("roles_key", "roles").put("sp.signature_private_key", SPOCK_KEY)
                .put("sp.signature_private_key_password", "changeit").put("path.home", ".").build();

        HTTPSamlAuthenticator samlAuthenticator = new HTTPSamlAuthenticator(settings, null);

        AuthCredentials authCredentials = new AuthCredentials("horst");
        authCredentials.addAttribute("attr.jwt.sub", "horst");
        authCredentials.addAttribute("attr.jwt.saml_nif", NameIDType.UNSPECIFIED);
        authCredentials.addAttribute("attr.jwt.saml_si", "si123");

        String logoutUrl = samlAuthenticator.buildLogoutUrl(authCredentials);

        mockSamlIdpServer.handleSloGetRequestURI(logoutUrl);

    }

    @Test
    public void initialConnectionFailureTest() throws Exception {
        try (MockSamlIdpServer mockSamlIdpServer = new MockSamlIdpServer()) {

            Settings settings = Settings.builder().put(IDP_METADATA_URL, mockSamlIdpServer.getMetadataUri())
                    .put("idp.min_refresh_delay", 100)
                    .put("kibana_url", "http://wherever").put("idp.entity_id", mockSamlIdpServer.getIdpEntityId())
                    .put("exchange_key", "abc").put("roles_key", "roles").put("path.home", ".").build();

            HTTPSamlAuthenticator samlAuthenticator = new HTTPSamlAuthenticator(settings, null);

            RestRequest restRequest = new FakeRestRequest(ImmutableMap.of(), new HashMap<String, String>());
            TestRestChannel restChannel = new TestRestChannel(restRequest);
            samlAuthenticator.reRequestAuthentication(restChannel, null);

            Assert.assertNull(restChannel.response);

            mockSamlIdpServer.start();

            mockSamlIdpServer.setSignResponses(true);
            mockSamlIdpServer.loadSigningKeys("saml/kirk-keystore.jks", "kirk");
            mockSamlIdpServer.setAuthenticateUser("horst");
            mockSamlIdpServer.setEndpointQueryString(null);

            Thread.sleep(500);

            AuthenticateHeaders authenticateHeaders = getAutenticateHeaders(samlAuthenticator);

            String encodedSamlResponse = mockSamlIdpServer.handleSsoGetRequestURI(authenticateHeaders.location);

            RestRequest tokenRestRequest = buildTokenExchangeRestRequest(encodedSamlResponse, authenticateHeaders);
            TestRestChannel tokenRestChannel = new TestRestChannel(tokenRestRequest);

            samlAuthenticator.reRequestAuthentication(tokenRestChannel, null);

            String responseJson = new String(BytesReference.toBytes(tokenRestChannel.response.content()));
            HashMap<String, Object> response = DefaultObjectMapper.objectMapper.readValue(responseJson,
                    new TypeReference<HashMap<String, Object>>() {
                    });
            String authorization = (String) response.get("authorization");

            Assert.assertNotNull("Expected authorization attribute in JSON: " + responseJson, authorization);

            JwsJwtCompactConsumer jwtConsumer = new JwsJwtCompactConsumer(authorization.replaceAll("\\s*bearer\\s*", ""));
            JwtToken jwt = jwtConsumer.getJwtToken();

            Assert.assertEquals("horst", jwt.getClaim("sub"));
        }
    }

    private AuthenticateHeaders getAutenticateHeaders(HTTPSamlAuthenticator samlAuthenticator) {
        RestRequest restRequest = new FakeRestRequest(ImmutableMap.of(), new HashMap<String, String>());
        TestRestChannel restChannel = new TestRestChannel(restRequest);

        samlAuthenticator.reRequestAuthentication(restChannel, null);

        List<String> wwwAuthenticateHeaders = restChannel.response.getHeaders().get("WWW-Authenticate");

        Assert.assertNotNull(wwwAuthenticateHeaders);
        Assert.assertEquals("More than one WWW-Authenticate header: " + wwwAuthenticateHeaders, 1,
                wwwAuthenticateHeaders.size());

        String wwwAuthenticateHeader = wwwAuthenticateHeaders.get(0);

        Matcher wwwAuthenticateHeaderMatcher = WWW_AUTHENTICATE_PATTERN.matcher(wwwAuthenticateHeader);

        if (!wwwAuthenticateHeaderMatcher.matches()) {
            Assert.fail("Invalid WWW-Authenticate header: " + wwwAuthenticateHeader);
        }

        Assert.assertEquals("X-Security-IdP", wwwAuthenticateHeaderMatcher.group(1));
        Assert.assertEquals("location", wwwAuthenticateHeaderMatcher.group(4));
        Assert.assertEquals("requestId", wwwAuthenticateHeaderMatcher.group(6));

        String location = wwwAuthenticateHeaderMatcher.group(5);
        String requestId = wwwAuthenticateHeaderMatcher.group(7);

        return new AuthenticateHeaders(location, requestId);
    }

    private RestRequest buildTokenExchangeRestRequest(String encodedSamlResponse,
            AuthenticateHeaders authenticateHeaders) {
        return buildTokenExchangeRestRequest(encodedSamlResponse, authenticateHeaders, "/opendistrosecurity/saml/acs");
    }

    private RestRequest buildTokenExchangeRestRequest(String encodedSamlResponse,
            AuthenticateHeaders authenticateHeaders, String acsEndpoint) {
        String authtokenPostJson;

        if (authenticateHeaders != null) {
            authtokenPostJson = "{\"SAMLResponse\": \"" + encodedSamlResponse + "\", \"RequestId\": \""
                    + authenticateHeaders.requestId + "\"}";
        } else {
            authtokenPostJson = "{\"SAMLResponse\": \"" + encodedSamlResponse
                    + "\", \"RequestId\": null, \"acsEndpoint\": \"" + acsEndpoint + "\" }";
        }

        return new FakeRestRequest.Builder().withPath("/_opendistro/_security/api/authtoken").withMethod(Method.POST)
                .withContent(new BytesArray(authtokenPostJson))
                .withHeaders(ImmutableMap.of("Content-Type", "application/json")).build();
    }

    @BeforeClass
    public static void initSpSigningKeys() {
        try {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

            KeyStore keyStore = KeyStore.getInstance("JKS");
            InputStream keyStream = new FileInputStream(
                    FileHelper.getAbsoluteFilePathFromClassPath("saml/spock-keystore.jks").toFile());

            keyStore.load(keyStream, "changeit".toCharArray());
            kmf.init(keyStore, "changeit".toCharArray());

            spSigningCertificate = (X509Certificate) keyStore.getCertificate("spock");

            spSigningPrivateKey = (PrivateKey) keyStore.getKey("spock", "changeit".toCharArray());

        } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | IOException
                | UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }
    }

    static class TestRestChannel implements RestChannel {

        final RestRequest restRequest;
        RestResponse response;

        TestRestChannel(RestRequest restRequest) {
            this.restRequest = restRequest;
        }

        @Override
        public XContentBuilder newBuilder() throws IOException {
            return null;
        }

        @Override
        public XContentBuilder newErrorBuilder() throws IOException {
            return null;
        }

        @Override
        public XContentBuilder newBuilder(XContentType xContentType, boolean useFiltering) throws IOException {
            return null;
        }

        @Override
        public BytesStreamOutput bytesOutput() {
            return null;
        }

        @Override
        public RestRequest request() {
            return restRequest;
        }

        @Override
        public boolean detailedErrorsEnabled() {
            return false;
        }

        @Override
        public void sendResponse(RestResponse response) {
            this.response = response;

        }

        @Override
        public XContentBuilder newBuilder(XContentType xContentType, XContentType responseContentType, boolean useFiltering) throws IOException {
            return null;
        }

    }

    static class AuthenticateHeaders {
        final String location;
        final String requestId;

        AuthenticateHeaders(String location, String requestId) {
            this.location = location;
            this.requestId = requestId;
        }
    }
}
