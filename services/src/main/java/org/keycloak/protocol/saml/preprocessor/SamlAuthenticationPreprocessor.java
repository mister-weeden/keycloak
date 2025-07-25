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
package org.keycloak.protocol.saml.preprocessor;

import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.dom.saml.v2.protocol.LogoutRequestType;
import org.keycloak.dom.saml.v2.protocol.StatusResponseType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Provider interface for SAML authentication preprocessing.
 * 
 * @author <a href="mailto:gideon.caranzo@thalesgroup.com">Gideon Caranzo</a>
 *
 */
public interface SamlAuthenticationPreprocessor extends Provider, ProviderFactory<SamlAuthenticationPreprocessor> {

    /**
     * Called before a login request is processed.
     */
    default AuthnRequestType beforeProcessingLoginRequest(AuthnRequestType authnRequest,
            AuthenticationSessionModel authSession) {
        return authnRequest;
    }

    /**
     * Called before a logout request is processed.
     * 
     * @param clientSession can be null if client is not applicable (e.g. when used within identity broker)
     */
    default LogoutRequestType beforeProcessingLogoutRequest(LogoutRequestType logoutRequest,
            UserSessionModel authSession, AuthenticatedClientSessionModel clientSession) {
        return logoutRequest;
    }

    /**
     * Called before a login request is sent.
     */
    default AuthnRequestType beforeSendingLoginRequest(AuthnRequestType authnRequest,
            AuthenticationSessionModel clientSession) {
        return authnRequest;
    }

    /**
     * Called before a logout request is sent.
     * 
     * @param clientSession can be null if client is not applicable (e.g. when used within identity broker)
     */
    default LogoutRequestType beforeSendingLogoutRequest(LogoutRequestType logoutRequest,
            UserSessionModel authSession, AuthenticatedClientSessionModel clientSession) {
        return logoutRequest;
    }

    /**
     * Called before a login response is processed.
     */
    default StatusResponseType beforeProcessingLoginResponse(StatusResponseType statusResponse,
            AuthenticationSessionModel authSession) {
        return statusResponse;
    }

    /**
     * Called before a response is sent back to the client.
     */
    default StatusResponseType beforeSendingResponse(StatusResponseType statusResponse,
            AuthenticatedClientSessionModel clientSession) {
        return statusResponse;
    }

}
