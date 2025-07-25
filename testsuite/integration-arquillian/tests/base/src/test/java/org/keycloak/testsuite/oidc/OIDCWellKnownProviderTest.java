/*
 * Copyright 2016 Scott Weeden and/or his affiliates
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

package org.keycloak.testsuite.oidc;

import jakarta.ws.rs.client.Client;
import org.junit.Test;
import org.keycloak.protocol.oidc.OIDCWellKnownProviderFactory;
import org.keycloak.protocol.oidc.representations.MTLSEndpointAliases;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.util.AdminClientUtil;
import org.keycloak.testsuite.util.oauth.OAuthClient;
import org.keycloak.testsuite.wellknown.CustomOIDCWellKnownProviderFactory;

import java.io.IOException;
import java.util.Map;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class OIDCWellKnownProviderTest extends AbstractWellKnownProviderTest {

    protected String getWellKnownProviderId() {
        return OIDCWellKnownProviderFactory.PROVIDER_ID;
    }

    @Test
    public void testDefaultProviderCustomizations() throws IOException {
        Client client = AdminClientUtil.createResteasyClient();
        try {
            OIDCConfigurationRepresentation oidcConfig = getOIDCDiscoveryRepresentation(client, OAuthClient.AUTH_SERVER_ROOT);

            // Assert that CustomOIDCWellKnownProvider was used as a prioritized provider over default OIDCWellKnownProvider
            MTLSEndpointAliases mtlsEndpointAliases = oidcConfig.getMtlsEndpointAliases();
            Assert.assertEquals("https://placeholder-host-set-by-testsuite-provider/registration", mtlsEndpointAliases.getRegistrationEndpoint());
            Assert.assertEquals("bar", oidcConfig.getOtherClaims().get("foo"));

            // Assert some configuration was overriden
            Assert.assertEquals("some-new-property-value", oidcConfig.getOtherClaims().get("some-new-property"));
            Assert.assertEquals("nested-value", ((Map) oidcConfig.getOtherClaims().get("some-new-property-compound")).get("nested1"));
            Assert.assertNames(oidcConfig.getIntrospectionEndpointAuthMethodsSupported(), "private_key_jwt", "client_secret_jwt", "tls_client_auth", "custom_nonexisting_authenticator");

            // Exact names already tested in OIDC
            assertScopesSupportedMatchesWithRealm(oidcConfig);

            // Temporarily disable client scopes
            getTestingClient().testing().setSystemPropertyOnServer(CustomOIDCWellKnownProviderFactory.INCLUDE_CLIENT_SCOPES, "false");
            oidcConfig = getOIDCDiscoveryRepresentation(client, OAuthClient.AUTH_SERVER_ROOT);
            Assert.assertNull(oidcConfig.getScopesSupported());
        } finally {
            getTestingClient().testing().setSystemPropertyOnServer(CustomOIDCWellKnownProviderFactory.INCLUDE_CLIENT_SCOPES, null);
            client.close();
        }
    }

}
