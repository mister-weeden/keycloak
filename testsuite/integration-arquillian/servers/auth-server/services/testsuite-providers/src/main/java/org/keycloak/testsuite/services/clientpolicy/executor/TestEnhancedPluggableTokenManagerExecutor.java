/*
 * Copyright 2023 Scott Weeden and/or his affiliates
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

package org.keycloak.testsuite.services.clientpolicy.executor;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.idm.ClientPolicyExecutorConfigurationRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.context.TokenResponseContext;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider;

/**
 * @author <a href="mailto:takashi.norimatsu.ws@hitachi.com">Takashi Norimatsu</a>
 */
public class TestEnhancedPluggableTokenManagerExecutor implements ClientPolicyExecutorProvider<ClientPolicyExecutorConfigurationRepresentation> {

    private static final Logger logger = Logger.getLogger(TestEnhancedPluggableTokenManagerExecutor.class);

    protected final KeycloakSession session;

    public TestEnhancedPluggableTokenManagerExecutor(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public String getProviderId() {
        return TestEnhancedPluggableTokenManagerExecutorFactory.PROVIDER_ID;
    }

    @Override
    public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {
        ClientPolicyEvent event = context.getEvent();

        if (event.equals(ClientPolicyEvent.TOKEN_RESPONSE)) {
            TokenResponseContext tokenResponseContext = (TokenResponseContext)context;
            dropSubClaimAndBuildTokenResponse(tokenResponseContext.getAccessTokenResponseBuilder());
        }
    }

    private void dropSubClaimAndBuildTokenResponse(TokenManager.AccessTokenResponseBuilder builder) throws ClientPolicyException {
        builder.getAccessToken().subject(null);
        builder.build();
    }

}
