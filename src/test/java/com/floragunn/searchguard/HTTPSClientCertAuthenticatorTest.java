package com.floragunn.searchguard;

import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.http.netty.NettyHttpRequest;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import com.floragunn.searchguard.authentication.AuthCredentials;
import com.floragunn.searchguard.authentication.AuthException;
import com.floragunn.searchguard.authentication.User;
import com.floragunn.searchguard.authentication.backend.AuthenticationBackend;
import com.floragunn.searchguard.authentication.backend.simple.AlwaysSucceedAuthenticationBackend;
import com.floragunn.searchguard.authentication.http.clientcert.HTTPSClientCertAuthenticator;
import com.floragunn.searchguard.authorization.Authorizator;
import com.floragunn.searchguard.authorization.simple.NoRolesAuthorizator;
import com.floragunn.searchguard.http.netty.MutualSSLHandler.DefaultHttpsRequest;
import com.floragunn.searchguard.util.ConfigConstants;

import static org.mockito.Mockito.*;

public class HTTPSClientCertAuthenticatorTest {

	@Test
	public void testSimpleUser() throws Exception {
		
		AuthenticationBackend ab = new AlwaysSucceedAuthenticationBackend();
		Authorizator az = new NoRolesAuthorizator();
		
		
		
		NettyHttpRequest nr = mock(NettyHttpRequest.class);
		DefaultHttpsRequest dhr = mock(DefaultHttpsRequest.class);
		sun.security.x509.X500Name x500 = new sun.security.x509.X500Name("CN=Max Mustermann, O=INRIA, C=FR");
		
		when(nr.request()).thenReturn(dhr);
		when(dhr.getPrincipal()).thenReturn(x500);
		
		final Settings settings = ImmutableSettings.settingsBuilder()
                .put(ConfigConstants.SEARCHGUARD_AUTHENTICATION_HTTPS_CLIENTCERT_ATTRIBUTENAME, "cn")
                .build();
		
		HTTPSClientCertAuthenticator auth = new HTTPSClientCertAuthenticator(settings);
		User user = auth.authenticate(nr, null, ab, az);
		Assert.assertNotNull(user);
		Assert.assertEquals("Max Mustermann", user.getName());
		
	}
	
	@Test
	public void testSimpleUserNoCN() throws Exception {
		
		AuthenticationBackend ab = new AlwaysSucceedAuthenticationBackend();
		Authorizator az = new NoRolesAuthorizator();
		
		
		
		NettyHttpRequest nr = mock(NettyHttpRequest.class);
		DefaultHttpsRequest dhr = mock(DefaultHttpsRequest.class);
		sun.security.x509.X500Name x500 = new sun.security.x509.X500Name("CN=Max Mustermann, O=INRIA, C=FR");
		
		
		when(nr.request()).thenReturn(dhr);
		when(dhr.getPrincipal()).thenReturn(x500);

		
		final Settings settings = ImmutableSettings.settingsBuilder()
                .put(ConfigConstants.SEARCHGUARD_AUTHENTICATION_HTTPS_CLIENTCERT_ATTRIBUTENAME, "ff")
                .build();
		
		HTTPSClientCertAuthenticator auth = new HTTPSClientCertAuthenticator(settings);
		User user = auth.authenticate(nr, null, ab, az);
		Assert.assertNotNull(user);
		Assert.assertNotEquals("Max Mustermann", user.getName());
		Assert.assertEquals("CN=Max Mustermann, O=INRIA, C=FR", user.getName());
		
	}
	
	@Test
	public void testSimpleUser2() throws Exception {
		
		AuthenticationBackend ab = new AlwaysSucceedAuthenticationBackend();
		Authorizator az = new NoRolesAuthorizator();
		
		
		
		NettyHttpRequest nr = mock(NettyHttpRequest.class);
		DefaultHttpsRequest dhr = mock(DefaultHttpsRequest.class);
		sun.security.x509.X500Name x500 = new sun.security.x509.X500Name("CN=Max Mustermann, O=INRIA, C=FR");
		
		
		when(nr.request()).thenReturn(dhr);
		when(dhr.getPrincipal()).thenReturn(x500);
		
		
		final Settings settings = ImmutableSettings.settingsBuilder()
                .put(ConfigConstants.SEARCHGUARD_AUTHENTICATION_HTTPS_CLIENTCERT_ATTRIBUTENAME, "c")
                .build();
		
		HTTPSClientCertAuthenticator auth = new HTTPSClientCertAuthenticator(settings);
		User user = auth.authenticate(nr, null, ab, az);
		Assert.assertNotNull(user);
		Assert.assertEquals("FR", user.getName());	
	}
	
}
