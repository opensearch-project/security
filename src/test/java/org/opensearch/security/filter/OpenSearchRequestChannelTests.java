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
import java.util.Optional;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.auditlog.helper.MockRestRequest;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;

@RunWith(MockitoJUnitRunner.class)
public class OpenSearchRequestChannelTests {

    @Mock
    public RestRequest restRequest;

    @Mock
    public RestChannel restChannel;

    @Mock
    public SecurityResponse response;

    private OpenSearchRequestChannel osRequest;

    @Before
    public void before() {
        osRequest = (OpenSearchRequestChannel) SecurityRequestFactory.from(restRequest, restChannel);
    }

    @Test
    public void testBreakEncapsulation() {
        assertThat(osRequest.breakEncapsulationForChannel(), equalTo(restChannel));
        assertThat(osRequest.breakEncapsulationForRequest(), equalTo(restRequest));
    }

    @Test
    public void testGetQueuedResponse() {
        assertThat(osRequest.getQueuedResponse(), equalTo(Optional.empty()));

        osRequest.queueForSending(response);

        assertThat(osRequest.getQueuedResponse().get(), equalTo(response));
    }


    // @Test
    // public void getHeaders() {
    //     final RestRequest restRequest = mock(RestRequest.class);
    //     final RestChannel restChannel = mock(RestChannel.class);
    //     final OpenSearchRequestChannel osRequest = (OpenSearchRequestChannel) SecurityRequestFactory.from(restRequest, restChannel);

    //     osRequest.breakEncapsulationForChannel();

    //     when(restRequest.getHeaders()).thenReturn();

    //     final Map<String,List<String>> headers = osRequest.getHeaders();
    //     assertThat(headers.keySet(), equalTo(List.of("a", "b")));
    //     assertThat(headers.values(), equalTo(List.of(List.of("1", "2"), List.of("3"))));

    //     final String value = osRequest.header("a");
    //     assertThat(value, equalTo("1"));

    //     final String valueCaseInsensitive = osRequest.header("A");
    //     assertThat(valueCaseInsensitive, equalTo("1"));

    //     verify(restRequest).getHeaders();
    // }

}
