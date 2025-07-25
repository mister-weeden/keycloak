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

package org.keycloak.testsuite.oidc.flows;

import org.junit.Before;
import org.keycloak.events.Details;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.idm.EventRepresentation;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.util.oauth.AuthorizationEndpointResponse;

import java.util.Collections;
import java.util.List;

/**
 * Test for response_type=none
 *
 * @author <a href="mailto:ggrazian@redhat.com">Giuseppe Graziano</a>
 */
public class OIDCBasicResponseTypeNoneTest extends AbstractOIDCResponseTypeTest {

    @Before
    public void clientConfiguration() {
        clientManagerBuilder().standardFlow(true).implicitFlow(false);

        oauth.clientId("test-app");
        oauth.responseType(OIDCResponseType.NONE);
    }


    @Override
    protected boolean isFragment() {
        return false;
    }

    @Override
    protected List<IDToken> testAuthzResponseAndRetrieveIDTokens(AuthorizationEndpointResponse authzResponse, EventRepresentation loginEvent) {
        Assert.assertEquals(OIDCResponseType.NONE, loginEvent.getDetails().get(Details.RESPONSE_TYPE));

        Assert.assertNull(authzResponse.getCode());
        Assert.assertNull(authzResponse.getAccessToken());
        Assert.assertNull(authzResponse.getIdToken());
        return Collections.emptyList();
    }
}
