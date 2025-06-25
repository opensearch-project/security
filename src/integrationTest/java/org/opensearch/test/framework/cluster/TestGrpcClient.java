package org.opensearch.test.framework.cluster;

import io.grpc.ManagedChannelBuilder;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpUriRequest;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.routing.HttpRoutePlanner;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class TestGrpcClient {
    private static final Logger log = LogManager.getLogger(TestRestClient.class);

    private boolean enableHTTPClientSSL;
    private boolean sendHTTPClientCertificate;
    private InetSocketAddress nodeHttpAddress;
    private RequestConfig requestConfig;
    private List<Header> headers = new ArrayList<>();
    private SSLContext sslContext;

    private final InetAddress sourceInetAddress;

    public TestGrpcClient(
            InetSocketAddress nodeHttpAddress,
            List<Header> headers,
            SSLContext sslContext,
            InetAddress sourceInetAddress,
            boolean enableHTTPClientSSL,
            boolean sendHTTPClientCertificate
    ) {
        this.nodeHttpAddress = nodeHttpAddress;
        this.headers.addAll(headers);
        this.sslContext = sslContext;
        this.sourceInetAddress = sourceInetAddress;
        this.enableHTTPClientSSL = enableHTTPClientSSL;
        this.sendHTTPClientCertificate = sendHTTPClientCertificate;
    }

    public TestRestClient.HttpResponse get(String path, Header... headers) {
        return executeRequest(new HttpGet(getHttpServerUri() + "/" + path), headers);
    }

    public TestRestClient.HttpResponse executeRequest(HttpUriRequest uriRequest, Header... requestSpecificHeaders) {
        try (CloseableHttpClient httpClient = getHTTPClient()) {

            if (requestSpecificHeaders != null && requestSpecificHeaders.length > 0) {
                for (int i = 0; i < requestSpecificHeaders.length; i++) {
                    Header h = requestSpecificHeaders[i];
                    uriRequest.addHeader(h);
                }
            }

            for (Header header : headers) {
                uriRequest.addHeader(header);
            }

            TestRestClient.HttpResponse res = new TestRestClient.HttpResponse(httpClient.execute(uriRequest));
            log.debug(res.getBody());
            return res;
        } catch (IOException e) {
            throw new RestClientException("Error occured during HTTP request execution", e);
        }
    }

    public final String getHttpServerUri() {
        return "http" + (enableHTTPClientSSL ? "s" : "") + "://" + nodeHttpAddress.getHostString() + ":" + nodeHttpAddress.getPort();
    }

    protected final CloseableHttpClient getHTTPClient() {
        // ManagedChannelBuilder.forAddress(host, port);
        HttpRoutePlanner routePlanner = Optional.ofNullable(sourceInetAddress).map(LocalAddressRoutePlanner::new).orElse(null);
        var factory = new CloseableHttpClientFactory(sslContext, requestConfig, routePlanner, null);
        return factory.getHTTPClient();
    }
}
