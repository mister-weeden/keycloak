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

package org.keycloak.services.clientpolicy.executor;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.Profile;
import org.keycloak.common.VerificationException;
import org.keycloak.common.Profile.Feature;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.provider.EnvironmentDependentProviderFactory;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.representations.dpop.DPoP;
import org.keycloak.representations.idm.ClientPolicyExecutorConfigurationRepresentation;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.context.ClientCRUDContext;
import org.keycloak.services.clientpolicy.context.TokenRefreshContext;
import org.keycloak.services.clientpolicy.context.TokenRevokeContext;
import org.keycloak.services.clientpolicy.context.UserInfoRequestContext;
import org.keycloak.services.util.DPoPUtil;

import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.ws.rs.core.MultivaluedMap;

public class DPoPBindEnforcerExecutor implements ClientPolicyExecutorProvider<DPoPBindEnforcerExecutor.Configuration> {

    private static final Logger logger = Logger.getLogger(DPoPBindEnforcerExecutor.class);

    private final KeycloakSession session;
    private Configuration configuration;

    public DPoPBindEnforcerExecutor(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void setupConfiguration(Configuration config) {
        this.configuration = config;
    }

    @Override
    public Class<Configuration> getExecutorConfigurationClass() {
        return Configuration.class;
    }

    public static class Configuration extends ClientPolicyExecutorConfigurationRepresentation {
        @JsonProperty("auto-configure")
        protected Boolean autoConfigure;

        public Boolean isAutoConfigure() {
            return autoConfigure;
        }

        public void setAutoConfigure(Boolean autoConfigure) {
            this.autoConfigure = autoConfigure;
        }
    }

    @Override
    public String getProviderId() {
        return DPoPBindEnforcerExecutorFactory.PROVIDER_ID;
    }

    @Override
    public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {
        if (!Profile.isFeatureEnabled(Feature.DPOP)) {
            logger.warnf("DPoP executor is used, but DPOP feature is disabled. So DPOP is not enforced for the clients. " +
                    "Please enable DPOP feature in order to be able to have DPOP checks applied.");
            return;
        }

        HttpRequest request = session.getContext().getHttpRequest();
        switch (context.getEvent()) {
            case REGISTER:
            case UPDATE:
                ClientCRUDContext clientUpdateContext = (ClientCRUDContext)context;
                autoConfigure(clientUpdateContext.getProposedClientRepresentation());
                validate(clientUpdateContext.getProposedClientRepresentation());
                break;
            case TOKEN_REQUEST:
            case TOKEN_REFRESH:
            case USERINFO_REQUEST:
            case BACKCHANNEL_TOKEN_REQUEST:
                // Codes for processing these requests verifies DPoP.
                // If this verification is done twice, DPoPReplayCheck fails. Therefore, the executor only checks existence of DPoP Proof
                if (request.getHttpHeaders().getHeaderString(DPoPUtil.DPOP_HTTP_HEADER) == null) {
                    throw new ClientPolicyException(OAuthErrorException.INVALID_DPOP_PROOF, "DPoP proof is missing");
                }
                break;
            case TOKEN_REVOKE:
                checkTokenRevoke((TokenRevokeContext) context, request);
            default:
                return;
        }
    }

    private void autoConfigure(ClientRepresentation rep) {
        if (configuration.isAutoConfigure()) {
            OIDCAdvancedConfigWrapper.fromClientRepresentation(rep).setUseDPoP(true);
        }
    }

    private void validate(ClientRepresentation rep) throws ClientPolicyException {
        boolean useDPoPToken = OIDCAdvancedConfigWrapper.fromClientRepresentation(rep).isUseDPoP();
        if (!useDPoPToken) {
            throw new ClientPolicyException(OAuthErrorException.INVALID_CLIENT_METADATA, "Invalid client metadata: DPoP token in disabled");
        }
    }

    private void checkTokenRevoke(TokenRevokeContext context, HttpRequest request) throws ClientPolicyException {
        DPoP dPoP = retrieveAndVerifyDPoP(request);

        MultivaluedMap<String, String> revokeParameters = context.getParams();
        String encodedRevokeToken = revokeParameters.getFirst("token");

        AccessToken token = session.tokens().decode(encodedRevokeToken, AccessToken.class);
        if (token == null) {
            // this executor does not treat this error case.
            return;
        }

        validateBinding(token, dPoP);
    }

    private DPoP retrieveAndVerifyDPoP(HttpRequest request) throws ClientPolicyException {
        DPoP dPoP = null;
        try {
            dPoP = new DPoPUtil.Validator(session).request(request).uriInfo(session.getContext().getUri()).validate();
        } catch (VerificationException ex) {
            logger.tracev("dpop verification error = {0}", ex.getMessage());
            throw new ClientPolicyException(OAuthErrorException.INVALID_DPOP_PROOF, ex.getMessage());
        }
        return dPoP;
    }

    private void validateBinding(AccessToken token, DPoP dPoP) throws ClientPolicyException {
        try {
            DPoPUtil.validateBinding(token, dPoP);
        } catch (VerificationException ex) {
            logger.tracev("dpop bind refresh token verification error = {0}", ex.getMessage());
            throw new ClientPolicyException(OAuthErrorException.INVALID_TOKEN, "DPoP proof and token binding verification failed");
        }
    }
}
