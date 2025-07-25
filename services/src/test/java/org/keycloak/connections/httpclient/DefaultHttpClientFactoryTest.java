/*
 * Copyright 2019 Scott Weeden and/or his affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.connections.httpclient;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import javax.net.ssl.SSLPeerUnverifiedException;

import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Assume;
import org.junit.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resteasy.ResteasyKeycloakSession;
import org.keycloak.services.resteasy.ResteasyKeycloakSessionFactory;
import org.keycloak.utils.ScopeUtil;

public class DefaultHttpClientFactoryTest {
	private static final String DISABLE_TRUST_MANAGER_PROPERTY = "disable-trust-manager";
	private static final String TEST_DOMAIN = "keycloak.org";

	@Test
	public void createHttpClientProviderWithDisableTrustManager() throws IOException{
		Map<String, String> values = new HashMap<>();
		values.put(DISABLE_TRUST_MANAGER_PROPERTY, "true");
		DefaultHttpClientFactory factory = new DefaultHttpClientFactory();
		factory.init(ScopeUtil.createScope(values));
		KeycloakSession session = new ResteasyKeycloakSession(new ResteasyKeycloakSessionFactory());
		HttpClientProvider provider = factory.create(session);
        Optional<String> testURL = getTestURL();
        Assume.assumeTrue( "Could not get test url for domain", testURL.isPresent() );
		try (CloseableHttpClient httpClient = provider.getHttpClient();
          CloseableHttpResponse response = httpClient.execute(new HttpGet(testURL.get()))) {
    		assertEquals(HttpStatus.SC_NOT_FOUND,response.getStatusLine().getStatusCode());
		}
	}

	@Test(expected = SSLPeerUnverifiedException.class)
	public void createHttpClientProviderWithUnvailableURL() throws IOException {
		DefaultHttpClientFactory factory = new DefaultHttpClientFactory();
		factory.init(ScopeUtil.createScope(new HashMap<>()));
		KeycloakSession session = new ResteasyKeycloakSession(new ResteasyKeycloakSessionFactory());
		HttpClientProvider provider = factory.create(session);
		try (CloseableHttpClient httpClient = provider.getHttpClient()) {
			Optional<String> testURL = getTestURL();
			Assume.assumeTrue("Could not get test url for domain", testURL.isPresent());
			httpClient.execute(new HttpGet(testURL.get()));
		}
	}

	private Optional<String> getTestURL() {
		try {
			// Convert domain name to ip to make request by ip
			return Optional.of("https://" + InetAddress.getByName(TEST_DOMAIN).getHostAddress());
		} catch (UnknownHostException e) {
			return Optional.empty();
		}
	}

}
