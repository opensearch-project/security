/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
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

package com.floragunn.searchguard.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URL;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import org.apache.commons.io.IOUtils;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.netty.handler.codec.http.Cookie;
import org.elasticsearch.common.netty.handler.codec.http.CookieDecoder;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

import com.google.common.io.BaseEncoding;

public class SecurityUtil {

    private static final ESLogger log = Loggers.getLogger(SecurityUtil.class);
    private static final String[] PREFERRED_SSL_CIPHERS = { "TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" };
    private static final String[] PREFERRED_SSL_PROTOCOLS = { "TLSv1", "TLSv1.1", "TLSv1.2" };

    public static String[] ENABLED_SSL_PROTOCOLS = null;
    public static String[] ENABLED_SSL_CIPHERS = null;

    private SecurityUtil() {

    }

    static {
        try {
            final int aesMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES");

            if (aesMaxKeyLength < 256) {
                log.warn("AES 256 not supported, max key length for AES is " + aesMaxKeyLength
                        + ". To enable AES 256 install 'Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files'");
            }
        } catch (final NoSuchAlgorithmException e) {
            log.error("AES encryption not supported. " + e);

        }

        try {

            final SSLContext serverContext = SSLContext.getInstance("TLS");
            serverContext.init(null, null, null);
            final SSLEngine engine = serverContext.createSSLEngine();
            final List<String> supportedCipherSuites = new ArrayList<String>(Arrays.asList(engine.getSupportedCipherSuites()));
            final List<String> supportedProtocols = new ArrayList<String>(Arrays.asList(engine.getSupportedProtocols()));

            final List<String> preferredCipherSuites = Arrays.asList(PREFERRED_SSL_CIPHERS);
            final List<String> preferredProtocols = Arrays.asList(PREFERRED_SSL_PROTOCOLS);

            supportedCipherSuites.retainAll(preferredCipherSuites);
            supportedProtocols.retainAll(preferredProtocols);

            if (supportedCipherSuites.isEmpty()) {
                log.error("No usable SSL/TLS cipher suites found");
            } else {
                ENABLED_SSL_CIPHERS = supportedCipherSuites.toArray(new String[0]);
            }

            if (supportedProtocols.isEmpty()) {
                log.error("No usable SSL/TLS protocols found");
            } else {
                ENABLED_SSL_PROTOCOLS = supportedProtocols.toArray(new String[0]);
            }

            log.debug("Usable SSL/TLS protocols: {}", supportedProtocols);
            log.debug("Usable SSL/TLS cipher suites: {}", supportedCipherSuites);

        } catch (final Exception e) {
            log.error("Error while evaluating supported crypto", e);
        }
    }

    public static File getAbsoluteFilePathFromClassPath(final String fileNameFromClasspath) {

        File jaasConfigFile = null;
        final URL jaasConfigURL = SecurityUtil.class.getClassLoader().getResource(fileNameFromClasspath);
        if (jaasConfigURL != null) {
            try {
                jaasConfigFile = new File(URLDecoder.decode(jaasConfigURL.getFile(), "UTF-8"));
            } catch (final UnsupportedEncodingException e) {
                return null;
            }

            if (jaasConfigFile.exists() && jaasConfigFile.canRead()) {
                return jaasConfigFile;
            } else {
                log.error("Cannot read from {}, maybe the file does not exists? ", jaasConfigFile.getAbsolutePath());
            }

        } else {
            log.error("Failed to load " + fileNameFromClasspath);
        }

        return null;

    }

    public static boolean setSystemPropertyToAbsoluteFilePathFromClassPath(final String property, final String fileNameFromClasspath) {
        if (System.getProperty(property) == null) {
            File jaasConfigFile = null;
            final URL jaasConfigURL = SecurityUtil.class.getClassLoader().getResource(fileNameFromClasspath);
            if (jaasConfigURL != null) {
                try {
                    jaasConfigFile = new File(URLDecoder.decode(jaasConfigURL.getFile(), "UTF-8"));
                } catch (final UnsupportedEncodingException e) {
                    return false;
                }

                if (jaasConfigFile.exists() && jaasConfigFile.canRead()) {
                    System.setProperty(property, jaasConfigFile.getAbsolutePath());

                    log.debug("Load " + fileNameFromClasspath + " from {} ", jaasConfigFile.getAbsolutePath());
                    return true;
                } else {
                    log.error("Cannot read from {}, maybe the file does not exists? ", jaasConfigFile.getAbsolutePath());
                }

            } else {
                log.error("Failed to load " + fileNameFromClasspath);
            }
        } else {
            log.warn("Property " + property + " already set to " + System.getProperty(property));
        }

        return false;
    }

    public static boolean setSystemPropertyToAbsoluteFile(final String property, final String fileName) {
        if (System.getProperty(property) == null) {

            if (fileName == null) {
                log.error("Cannot set property " + property + " because filename is null");

                return false;
            }

            final File jaasConfigFile = new File(fileName).getAbsoluteFile();

            if (jaasConfigFile.exists() && jaasConfigFile.canRead()) {
                System.setProperty(property, jaasConfigFile.getAbsolutePath());

                log.debug("Load " + fileName + " from {} ", jaasConfigFile.getAbsolutePath());
                return true;
            } else {
                log.error("Cannot read from {}, maybe the file does not exists? ", jaasConfigFile.getAbsolutePath());
            }

        } else {
            log.warn("Property " + property + " already set to " + System.getProperty(property));
        }

        return false;
    }

    public static void send(final RestChannel channel, final RestStatus status, final String arg) {
        try {

            final XContentBuilder builder = channel.newBuilder();

            builder.startObject();
            builder.field("status", status.getStatus());

            if (arg != null && !arg.isEmpty()) {
                builder.field("message", arg);
            }

            builder.endObject();
            channel.sendResponse(new BytesRestResponse(status, builder));
        } catch (final Exception e) {
            log.error("Failed to send a response.", e);
            try {
                channel.sendResponse(new BytesRestResponse(channel, e));
            } catch (final IOException e1) {
                log.error("Failed to send a failure response.", e1);
            }
        }
    }

    public static boolean isWildcardMatch(final String toCheckForMatch, final String pattern, final boolean alsoViceVersa) {

        String escapedPattern = pattern.replace(".", "\\.").replace("*", ".*");
        Pattern regexPattern = Pattern.compile(escapedPattern);
        Matcher matcher = regexPattern.matcher(toCheckForMatch);
        final boolean normalMatch = matcher.matches();

        if (alsoViceVersa) {

            if (normalMatch) {
                return normalMatch;
            }

            escapedPattern = toCheckForMatch.replace(".", "\\.").replace("*", ".*");
            regexPattern = Pattern.compile(escapedPattern);
            matcher = regexPattern.matcher(pattern);
            return matcher.matches();

        } else {
            return normalMatch;
        }
    }

    public static void unbindAndCloseSilently(final LdapConnection connection) {
        if (connection == null) {
            return;
        }

        try {
            connection.unBind();
        } catch (final Exception e) {
            //ignore
        }

        try {
            connection.close();
        } catch (final Exception e) {
            //ignore
        }

    }

    public static String getSearchGuardSessionIdFromCookie(final RestRequest request) {

        final String cookies = request.header("Cookie");

        if (cookies != null) {

            final Set<Cookie> cookiesAsSet = new CookieDecoder().decode(cookies);

            log.trace("Cookies {}", cookiesAsSet);

            for (final Iterator iterator = cookiesAsSet.iterator(); iterator.hasNext();) {
                final Cookie cookie = (Cookie) iterator.next();
                if ("es_searchguard_session".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }

        }
        return null;
    }

    public static String encryptAndSerializeObject(final Serializable object, final SecretKey key) {

        if (object == null) {
            throw new IllegalArgumentException("object must not be null");
        }

        try {
            final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            final SealedObject sealedobject = new SealedObject(object, cipher);
            final ByteArrayOutputStream bos = new ByteArrayOutputStream();
            final ObjectOutputStream out = new ObjectOutputStream(bos);
            out.writeObject(sealedobject);
            final byte[] bytes = bos.toByteArray();
            return BaseEncoding.base64().encode(bytes);
        } catch (final Exception e) {
            log.error(e.toString(), e);
            throw new ElasticsearchException(e.toString());
        }
    }

    public static Serializable decryptAnDeserializeObject(final String string, final SecretKey key) {

        if (string == null) {
            throw new IllegalArgumentException("string must not be null");
        }

        try {
            final byte[] userr = BaseEncoding.base64().decode(string);
            final ByteArrayInputStream bis = new ByteArrayInputStream(userr);
            final ObjectInputStream in = new ObjectInputStream(bis);
            final SealedObject ud = (SealedObject) in.readObject();
            return (Serializable) ud.getObject(key);
        } catch (final Exception e) {
            log.error(e.toString(), e);
            throw new ElasticsearchException(e.toString());
        }
    }

    private static boolean isWindowsAdmin() {

        try {
            final Class ntSystemClass = Class.forName("com.sun.security.auth.module.NTSystem");
            final Object ntSystem = ntSystemClass.newInstance();
            final String[] groups = (String[]) ntSystemClass.getDeclaredMethod("getGroupIDs").invoke(ntSystem);
            for (final String group : groups) {
                if (group.equals("S-1-5-32-544")) {
                    return true;
                }
            }
            return false;
        } catch (final Exception e) {
            return false;
        }
    }

    public static boolean isRootUser() {

        boolean isRoot = false;

        int exitValue = -1;
        String result = null;

        try {
            final Process p = Runtime.getRuntime().exec("id -u");
            result = IOUtils.toString(p.getInputStream());
            exitValue = p.waitFor();
            p.destroy();
        } catch (final Exception e) {
            //ignore
        }

        if (exitValue == 0 && result != null) {
            isRoot = "0".equals(result.trim());
        }

        if (!isRoot) {
            return isWindowsAdmin();
        } else {
            return true;
        }
    }

    public static InetAddress getProxyResolvedHostAddressFromRequest(final RestRequest request, final Settings settings)
            throws UnknownHostException {

        // this.logger.debug(request.getClass().toString());

        final String oaddr = ((InetSocketAddress) request.getRemoteAddress()).getHostString();
        // this.logger.debug("original hostname: " + addr);

        String raddr = oaddr;

        if (oaddr == null || oaddr.isEmpty()) {
            throw new UnknownHostException("Original host is <null> or <empty>");
        }

        final InetAddress iaddr = InetAddress.getByName(oaddr);

        final String xForwardedForHeader = settings.get(ConfigConstants.SEARCHGUARD_HTTP_XFORWARDEDFOR_HEADER, "X-Forwarded-For");

        if (xForwardedForHeader != null && !xForwardedForHeader.isEmpty()) {

            final String xForwardedForValue = request.header(xForwardedForHeader);

            //logger.trace("xForwardedForHeader is " + xForwardedForHeader + ":" + xForwardedForValue);

            final String[] xForwardedTrustedProxies = settings.getAsArray(ConfigConstants.SEARCHGUARD_HTTP_XFORWARDEDFOR_TRUSTEDPROXIES);

            final boolean xForwardedEnforce = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_HTTP_XFORWARDEDFOR_ENFORCE, false);

            if (xForwardedForValue != null && !xForwardedForValue.isEmpty()) {
                final List<String> addresses = Arrays.asList(xForwardedForValue.replace(" ", "").split(","));
                final List<String> proxiesPassed = new ArrayList<String>(addresses.subList(1, addresses.size()));

                if (xForwardedTrustedProxies.length == 0) {
                    throw new UnknownHostException("No trusted proxies");
                }

                proxiesPassed.removeAll(Arrays.asList(xForwardedTrustedProxies));

                //logger.debug(proxiesPassed.size() + "/" + proxiesPassed);

                if (proxiesPassed.size() == 0 && (Arrays.asList(xForwardedTrustedProxies).contains(oaddr) || iaddr.isLoopbackAddress())) {

                    raddr = addresses.get(0).trim();

                } else {
                    throw new UnknownHostException("Not all proxies are trusted");
                }

            } else {
                if (xForwardedEnforce) {
                    throw new UnknownHostException("Forward header enforced but not present");
                }
            }

        }

        if (raddr == null || raddr.isEmpty()) {
            throw new UnknownHostException("Host is <null> or <empty>");
        }

        if (raddr.equals(oaddr)) {
            return iaddr;
        } else {
            // if null or "" then loopback is returned
            return InetAddress.getByName(raddr);
        }

    }
}
