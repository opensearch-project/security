package org.opensearch.security.filter;

import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.List;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.auditlog.helper.MockRestRequest;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;

@RunWith(MockitoJUnitRunner.class)
public class OpenSearchRequestTests {

    @Test
    public void getHeaders() {
        MockRestRequest restRequest = new MockRestRequest()
        final RestRequest restRequest = mock(RestRequest.class);
        final OpenSearchRequest osRequest = (OpenSearchRequest) SecurityRequestFactory.from(restRequest);

        when(restRequest.getHeaders()).thenReturn();

        final Map<String,List<String>> headers = osRequest.getHeaders();
        assertThat(headers.keySet(), equalTo(List.of("a", "b")));
        assertThat(headers.values(), equalTo(List.of(List.of("1", "2"), List.of("3"))));

        final String value = osRequest.header("a");
        assertThat(value, equalTo("1"));

        final String valueCaseInsensitive = osRequest.header("A");
        assertThat(valueCaseInsensitive, equalTo("1"));

        verify(restRequest).getHeaders();
    }

}
