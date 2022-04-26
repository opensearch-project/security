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

package org.opensearch.security.ssl.transport;

import java.lang.reflect.Method;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.SSLPeerUnverifiedException;

import io.netty.handler.ssl.SslHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.ExceptionsHelper;
import org.opensearch.OpenSearchException;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.ssl.SslExceptionHandler;
import org.opensearch.security.ssl.util.ExceptionUtils;
import org.opensearch.security.ssl.util.SSLRequestHelper;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TaskTransportChannel;
import org.opensearch.transport.TcpChannel;
import org.opensearch.transport.TcpTransportChannel;
import org.opensearch.transport.TransportChannel;
import org.opensearch.transport.TransportRequest;
import org.opensearch.transport.TransportRequestHandler;
import org.opensearch.transport.netty4.Netty4TcpChannel;

public class SecuritySSLRequestHandler<T extends TransportRequest>
implements TransportRequestHandler<T> {
    
    private final String action;
    private final TransportRequestHandler<T> actualHandler;
    private final ThreadPool threadPool;
    protected final Logger log = LogManager.getLogger(this.getClass());
    private final PrincipalExtractor principalExtractor;
    private final SslExceptionHandler errorHandler;
    private final SSLConfig SSLConfig;

    public SecuritySSLRequestHandler(String action, TransportRequestHandler<T> actualHandler,
            ThreadPool threadPool, final PrincipalExtractor principalExtractor, final SSLConfig SSLConfig,
                                               final SslExceptionHandler errorHandler) {

        super();
        this.action = action;
        this.actualHandler = actualHandler;
        this.threadPool = threadPool;
        this.principalExtractor = principalExtractor;
        this.SSLConfig = SSLConfig;
        this.errorHandler = errorHandler;
    }
    
    protected ThreadContext getThreadContext() {
        if(threadPool == null) {
            return null;
        }

        return threadPool.getThreadContext();
    }

    @Override
    public final void messageReceived(T request, TransportChannel channel, Task task) throws Exception {
        ThreadContext threadContext = getThreadContext() ;
      
        if(SSLRequestHelper.containsBadHeader(threadContext, "_opendistro_security_ssl_")) {
            final Exception exception = ExceptionUtils.createBadHeaderException();
            channel.sendResponse(exception);
            throw exception;
        }

        String channelType = channel.getChannelType();
        if (!channelType.equals("direct") && !channelType.equals("transport")) {
            channel = getInnerChannel(channel);
        }
 
        if (!"transport".equals(channel.getChannelType())) { //netty4
            messageReceivedDecorate(request, actualHandler, channel, task);
            return;
        }
        
        try {

            Netty4TcpChannel nettyChannel = null;

            if (channel instanceof TaskTransportChannel) {
                final TransportChannel inner = ((TaskTransportChannel) channel).getChannel();
                nettyChannel = (Netty4TcpChannel ) ((TcpTransportChannel) inner).getChannel();
            } else
            if (channel instanceof TcpTransportChannel) {
                final TcpChannel inner = ((TcpTransportChannel) channel).getChannel();
                nettyChannel = (Netty4TcpChannel) inner;
            } else {
                throw new Exception("Invalid channel of type "+channel.getClass()+ " ("+channel.getChannelType()+")");
            }
            
            final SslHandler sslhandler = (SslHandler) nettyChannel.getNettyChannel().pipeline().get("ssl_server");

            if (sslhandler == null) {
                if (SSLConfig.isDualModeEnabled()) {
                    log.info("Communication in dual mode. Skipping SSL handler check");
                    threadContext.putTransient(ConfigConstants.SECURITY_SSL_DUAL_MODE_SKIP_SECURITY, Boolean.TRUE);
                    messageReceivedDecorate(request, actualHandler, channel, task);
                    return;
                }
                final String msg = "No ssl handler found (SG 11)";
                //log.error(msg);
                final Exception exception = new OpenSearchException(msg);
                channel.sendResponse(exception);
                throw exception;
            }


            final Certificate[] peerCerts = sslhandler.engine().getSession().getPeerCertificates();
            final Certificate[] localCerts = sslhandler.engine().getSession().getLocalCertificates();
            
            if (peerCerts != null 
                    && peerCerts.length > 0 
                    && peerCerts[0] instanceof X509Certificate 
                    && localCerts != null && localCerts.length > 0 
                    && localCerts[0] instanceof X509Certificate) {
                final X509Certificate[] x509PeerCerts = Arrays.copyOf(peerCerts, peerCerts.length, X509Certificate[].class);
                final X509Certificate[] x509LocalCerts = Arrays.copyOf(localCerts, localCerts.length, X509Certificate[].class);
                final String principal = principalExtractor==null?null:principalExtractor.extractPrincipal(x509PeerCerts[0], PrincipalExtractor.Type.TRANSPORT);
                addAdditionalContextValues(action, request, x509LocalCerts, x509PeerCerts, principal);
                if(threadContext != null) {
                    //in the case of ssl plugin only: threadContext and principalExtractor are null
                    threadContext.putTransient("_opendistro_security_ssl_transport_principal", principal);
                    threadContext.putTransient("_opendistro_security_ssl_transport_peer_certificates", x509PeerCerts);
                    threadContext.putTransient("_opendistro_security_ssl_transport_local_certificates", x509LocalCerts);
                    threadContext.putTransient("_opendistro_security_ssl_transport_protocol", sslhandler.engine().getSession().getProtocol());
                    threadContext.putTransient("_opendistro_security_ssl_transport_cipher", sslhandler.engine().getSession().getCipherSuite());
                }
                messageReceivedDecorate(request, actualHandler, channel, task);
            } else {
                final String msg = "No X509 transport client certificates found (SG 12)";
                //log.error(msg);
                final Exception exception = new OpenSearchException(msg);
                errorHandler.logError(exception, request, action, task, 0);
                channel.sendResponse(exception);
                throw exception;
            }

        } catch (final SSLPeerUnverifiedException e) {
            errorHandler.logError(e, request, action, task, 0);
            final Exception exception = ExceptionsHelper.convertToOpenSearchException(e);
            channel.sendResponse(exception);
            throw exception;
        } catch (final Exception e) {
            errorHandler.logError(e, request, action, task, 0);
            throw e;
        }
        
    }

    protected TransportChannel getInnerChannel(TransportChannel transportChannel) throws Exception {
        try {
            Class wrappedChannelCls = transportChannel.getClass();
            Method getInnerChannel = wrappedChannelCls.getMethod("getInnerChannel");
            TransportChannel innerChannel = (TransportChannel)(getInnerChannel.invoke(transportChannel));
            log.debug("Using inner transport channel " + innerChannel.getChannelType());
            return innerChannel;
        } catch (NoSuchMethodException ex) {
            throw new RuntimeException("Unknown channel type " + transportChannel.getChannelType() + " does not implement getInnerChannel method.");
        }
    }
    
    protected void addAdditionalContextValues(final String action, final TransportRequest request, final X509Certificate[] localCerts, final X509Certificate[] peerCerts, final String principal)
            throws Exception {
        // no-op
    }
    
    protected void messageReceivedDecorate(final T request, final TransportRequestHandler<T> actualHandler, final TransportChannel transportChannel, Task task) throws Exception {
        actualHandler.messageReceived(request, transportChannel, task);
    }
}
