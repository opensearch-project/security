package org.opensearch.security.action.onbehalf;

import java.io.IOException;
import java.util.List;

import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.FailedNodeException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.nodes.TransportNodesAction;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.inject.Provider;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.BackendRegistry;
import org.opensearch.security.authtoken.jwt.JwtVendor;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportRequest;
import org.opensearch.transport.TransportService;
import org.opensearch.rest.BaseRestHandler;

import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.rest.RestStatus;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.ssl.SecurityKeyStore;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.client.node.NodeClient;
import org.opensearch.security.user.User;

import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class CreateOnBehalfOfToken extends BaseRestHandler {

    private final JwtVendor vendor;
    private final ThreadPool threadPool;

    public CreateOnBehalfOfToken(final Settings settings, final ThreadPool threadPool) {
        Settings testSettings =  Settings.builder()
        .put("signing_key", "1234567890123456")
        .put("encryption_key", "1234567890123456").build();

        this.vendor = new JwtVendor(testSettings, Optional.empty());
        this.threadPool = threadPool;
    }

	@Override
	public String getName() {
		return getClass().getSimpleName();
	}

	@Override
	public List<Route> routes() {
		return addRoutesPrefix(
            ImmutableList.of(
                    new Route(Method.POST, "/user/onbehalfof")
            )
        );
	}

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        switch (request.method()) {
            case POST:
                return handlePost(request, client);
            default:
                throw new IllegalArgumentException(request.method() + " not supported");
        }
    }

    private RestChannelConsumer handlePost(RestRequest request, NodeClient client) throws IOException {
        return new RestChannelConsumer() {
            @Override
            public void accept(RestChannel channel) throws Exception {
                final XContentBuilder builder = channel.newBuilder();
                BytesRestResponse response;
        
                try {
                    builder.startObject();
                    final User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                    builder.field("user_name", "nothing");
                    builder.field("user", user.toString());
                    final String token = vendor.createJwt("me", user.getName(), "self-issued", 60, List.of("1", "2", "3"));
                    builder.field("field_token", token);
                    builder.endObject();
        
                    response = new BytesRestResponse(RestStatus.OK, builder);
                } catch (final Exception exception) {
                    System.out.println(exception.toString());
                    builder.startObject()
                            .field("error", exception.toString())
                            .endObject();
        
                    response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
                }
                builder.close();
                channel.sendResponse(response);
            }
        };
    }

}
