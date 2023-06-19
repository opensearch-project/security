package org.opensearch.security.action.onbehalf;

import java.io.IOException;
import java.util.List;

import org.apache.cxf.rs.security.jose.jwt.JwtToken;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.greenrobot.eventbus.Subscribe;
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
import org.opensearch.security.securityconf.DynamicConfigModel;
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
import java.util.function.LongSupplier;
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

    private JwtVendor vendor;
    private final ThreadPool threadPool;
    private DynamicConfigModel dcm;

//    @Subscribe
//    public void onDynamicConfigModelChanged(DynamicConfigModel dcm) {
//        this.dcm = dcm;
//        this.vendor = new JwtVendor(dcm.getDynamicOnBehalfOfSettings(), Optional.empty());
//        //TODO: NULL CHECK\
//    }

    public CreateOnBehalfOfToken(final Settings settings, final ThreadPool threadPool, final JwtVendor vendor) {

        this.vendor = vendor;
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
                    final Map<String, Object> requestBody = request.contentOrSourceParamParser().map();
                    final String reason = (String)requestBody.getOrDefault("reason", null);

                    final Integer tokenDuration = Optional.ofNullable(requestBody.get("duration"))
                        .map(value -> (String)value)
                        .map(Integer::parseInt)
                        .map(value -> Math.min(value, 72 * 3600)) // Max duration is 72 hours
                        .orElse(24 * 3600); // Fallback to default;

                    final String source = "self-issued";
                    final User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        
                    builder.startObject();
                    builder.field("user", user.getName());
                    System.out.println("Ljl19970123");
                    System.out.println(user.getRoles().stream().collect(Collectors.toList()));
                    final String token = vendor.createJwt(/* TODO: Update the issuer to represent the cluster */"OpenSearch",
                        user.getName(),
                        source,
                        tokenDuration,
                        user.getSecurityRoles().stream().collect(Collectors.toList()));
                    builder.field("onBehalfOfToken", token);
                    builder.field("duration", tokenDuration);
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
