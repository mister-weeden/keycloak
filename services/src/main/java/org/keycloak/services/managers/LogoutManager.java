/*
 * Copyright 2016 Scott Weeden and or his affiliates
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
package org.keycloak.services.managers;

import org.jboss.logging.Logger;
import org.keycloak.TokenVerifier;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.cookie.CookieProvider;
import org.keycloak.cookie.CookieType;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.SystemClientUtil;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.oidc.BackchannelLogoutResponse;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.Urls;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.context.LogoutRequestContext;
import org.keycloak.services.resources.IdentityBrokerService;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.sessions.CommonClientSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.util.TokenUtil;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.keycloak.models.UserSessionModel.CORRESPONDING_SESSION_ID;
import static org.keycloak.services.managers.AuthenticationManager.CLIENT_LOGOUT_STATE;
import static org.keycloak.services.managers.AuthenticationManager.KEYCLOAK_LOGOUT_PROTOCOL;
import static org.keycloak.services.managers.AuthenticationManager.LOGOUT_INITIATING_IDP;
import static org.keycloak.services.managers.AuthenticationManager.LOGOUT_WITH_SYSTEM_CLIENT;
import static org.keycloak.services.managers.AuthenticationManager.expireIdentityCookie;
import static org.keycloak.services.managers.AuthenticationManager.expireRememberMeCookie;

/**
 * Handles logout operations extracted from AuthenticationManager
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 */
public class LogoutManager {
    
    private static final Logger logger = Logger.getLogger(LogoutManager.class);
    private static final TokenVerifier.Predicate<? super AccessToken> VALIDATE_IDENTITY_COOKIE = new TokenVerifier.TokenTypeCheck(List.of(TokenUtil.TOKEN_TYPE_KEYCLOAK_ID));
    
    public static boolean expireUserSessionCookie(KeycloakSession session, UserSessionModel userSession, RealmModel realm, UriInfo uriInfo, HttpHeaders headers, ClientConnection connection) {
        try {
            // check to see if any identity cookie is set with the same session and expire it if necessary
            String tokenString = session.getProvider(CookieProvider.class).get(CookieType.IDENTITY);
            if (tokenString == null) return true;

            TokenVerifier<AccessToken> verifier = TokenVerifier.create(tokenString, AccessToken.class)
              .realmUrl(Urls.realmIssuer(uriInfo.getBaseUri(), realm.getName()))
              .checkActive(false)
              .checkTokenType(false)
              .withChecks(VALIDATE_IDENTITY_COOKIE);

            String kid = verifier.getHeader().getKeyId();
            String algorithm = verifier.getHeader().getAlgorithm().name();

            SignatureVerifierContext signatureVerifier = session.getProvider(SignatureProvider.class, algorithm).verifier(kid);
            verifier.verifierContext(signatureVerifier);

            AccessToken token = verifier.verify().getToken();
            UserSessionModel cookieSession = session.sessions().getUserSession(realm, token.getSessionState());
            if (cookieSession == null || !cookieSession.getId().equals(userSession.getId())) return true;
            expireIdentityCookie(session);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static void backchannelLogout(KeycloakSession session, UserSessionModel userSession, boolean logoutBroker) {
        backchannelLogout(
                session,
                session.getContext().getRealm(),
                userSession,
                session.getContext().getUri(),
                session.getContext().getConnection(),
                session.getContext().getRequestHeaders(),
                logoutBroker
        );
    }

    public static BackchannelLogoutResponse backchannelLogout(KeycloakSession session, RealmModel realm,
            UserSessionModel userSession, UriInfo uriInfo,
            ClientConnection connection, HttpHeaders headers,
            boolean logoutBroker) {

        return backchannelLogout(session, realm, userSession, uriInfo, connection, headers, logoutBroker, userSession == null ? false : userSession.isOffline());
    }

    public static BackchannelLogoutResponse backchannelLogout(KeycloakSession session, RealmModel realm,
            UserSessionModel userSession, UriInfo uriInfo,
            ClientConnection connection, HttpHeaders headers,
            boolean logoutBroker,
            boolean offlineSession) {
        BackchannelLogoutResponse backchannelLogoutResponse = new BackchannelLogoutResponse();

        if (userSession == null) {
            backchannelLogoutResponse.setLocalLogoutSucceeded(true);
            return backchannelLogoutResponse;
        }
        if (userSession.getState() != UserSessionModel.State.LOGGING_OUT) {
            userSession.setState(UserSessionModel.State.LOGGING_OUT);
        }

        if (logger.isDebugEnabled()) {
            UserModel user = userSession.getUser();
            String username = user == null ? null : user.getUsername();
            logger.debugv("Logging out: {0} ({1}) offline: {2}", username, userSession.getId(),
                    userSession.isOffline());
        }

        boolean expireUserSessionCookieSucceeded =
                expireUserSessionCookie(session, userSession, realm, uriInfo, headers, connection);

        final AuthenticationSessionManager asm = new AuthenticationSessionManager(session);
        AuthenticationSessionModel logoutAuthSession =
                createOrJoinLogoutSession(session, realm, asm, userSession, false, false);

        boolean userSessionOnlyHasLoggedOutClients = false;
        try {
            backchannelLogoutResponse = backchannelLogoutAll(session, realm, userSession, logoutAuthSession, uriInfo,
                    headers, logoutBroker);
            userSessionOnlyHasLoggedOutClients =
                    checkUserSessionOnlyHasLoggedOutClients(realm, userSession, logoutAuthSession);
        } finally {
            logger.tracef("Removing logout session '%s' after backchannel logout", logoutAuthSession.getParentSession().getId());
            session.authenticationSessions().removeRootAuthenticationSession(realm, logoutAuthSession.getParentSession());
        }

        userSession.setState(UserSessionModel.State.LOGGED_OUT);

        if (offlineSession) {
            new UserSessionManager(session).revokeOfflineUserSession(userSession);

            // Check if "online" session still exists and remove it too
            String onlineUserSessionId = userSession.getNote(CORRESPONDING_SESSION_ID);
            UserSessionModel onlineUserSession = onlineUserSessionId != null ?
                    session.sessions().getUserSession(realm, onlineUserSessionId) :
                    session.sessions().getUserSession(realm, userSession.getId());

            if (onlineUserSession != null) {
                session.sessions().removeUserSession(realm, onlineUserSession);
            }
        } else {
            session.sessions().removeUserSession(realm, userSession);
        }
        backchannelLogoutResponse
                .setLocalLogoutSucceeded(expireUserSessionCookieSucceeded && userSessionOnlyHasLoggedOutClients);
        return backchannelLogoutResponse;
    }

    public static AuthenticationSessionModel createOrJoinLogoutSession(KeycloakSession session, RealmModel realm,
            final AuthenticationSessionManager asm, UserSessionModel userSession, boolean browserCookie, boolean initiateLogout) {
        AuthenticationSessionModel logoutSession = session.getContext().getAuthenticationSession();
        if (logoutSession != null && AuthenticationSessionModel.Action.LOGGING_OUT.name().equals(logoutSession.getAction())) {
            return logoutSession;
        }

        ClientModel client = session.getContext().getClient();
        if (client == null) {
            // Account management client is used as a placeholder
            client = SystemClientUtil.getSystemClient(realm);
        }

        String authSessionId;
        RootAuthenticationSessionModel rootLogoutSession = null;
        boolean browserCookiePresent = false;

        // Try to lookup current authSessionId from browser cookie. If doesn't exist, use the same as current userSession
        if (browserCookie) {
            rootLogoutSession = asm.getCurrentRootAuthenticationSession(realm);
        }
        if (rootLogoutSession != null) {
            authSessionId = rootLogoutSession.getId();
            browserCookiePresent = true;
        } else if (userSession != null) {
            authSessionId = userSession.getId();
            rootLogoutSession = session.authenticationSessions().getRootAuthenticationSession(realm, authSessionId);
        } else {
            authSessionId = KeycloakModelUtils.generateId();
        }

        if (rootLogoutSession == null) {
            rootLogoutSession = session.authenticationSessions().createRootAuthenticationSession(realm, authSessionId);
        }
        if (browserCookie && !browserCookiePresent) {
            // Update cookie if needed
            asm.setAuthSessionCookie(authSessionId);
        }

        // See if we have logoutAuthSession inside current rootSession. Create new if not
        Optional<AuthenticationSessionModel> found = rootLogoutSession.getAuthenticationSessions().values().stream()
                .filter( authSession -> AuthenticationSessionModel.Action.LOGGING_OUT.name().equals(authSession.getAction()))
                .findFirst();

        AuthenticationSessionModel logoutAuthSession = null, prevAuthSession = null;
        if (found.isPresent()) {
            prevAuthSession = found.get();
            if (!initiateLogout || client.getId().equals(prevAuthSession.getClient().getId())) {
                logoutAuthSession = prevAuthSession;
                logger.tracef("Found existing logout session for client '%s'. Authentication session id: %s", client.getClientId(), rootLogoutSession.getId());
            }
        }

        if (logoutAuthSession == null) {
            logoutAuthSession = rootLogoutSession.createAuthenticationSession(client);
            logoutAuthSession.setAction(AuthenticationSessionModel.Action.LOGGING_OUT.name());
            logger.tracef("Creating logout session for client '%s'. Authentication session id: %s", client.getClientId(), rootLogoutSession.getId());
            if (prevAuthSession != null) {
                // remove previous logout session for the other client
                rootLogoutSession.removeAuthenticationSessionByTabId(prevAuthSession.getTabId());
                logger.tracef("Removing previous logout session for client '%s' in %s", prevAuthSession.getClient().getClientId(), rootLogoutSession.getId());
            }
        }
        session.getContext().setAuthenticationSession(logoutAuthSession);
        session.getContext().setClient(client);

        return logoutAuthSession;
    }

    private static BackchannelLogoutResponse backchannelLogoutAll(KeycloakSession session, RealmModel realm,
            UserSessionModel userSession, AuthenticationSessionModel logoutAuthSession, UriInfo uriInfo,
            HttpHeaders headers, boolean logoutBroker) {
        BackchannelLogoutResponse backchannelLogoutResponse = new BackchannelLogoutResponse();

        for (AuthenticatedClientSessionModel clientSession : userSession.getAuthenticatedClientSessions().values()) {
            Response clientSessionLogoutResponse =
                    backchannelLogoutClientSession(session, realm, clientSession, logoutAuthSession, uriInfo, headers);

            String backchannelLogoutUrl =
                    OIDCAdvancedConfigWrapper.fromClientModel(clientSession.getClient()).getBackchannelLogoutUrl();

            BackchannelLogoutResponse.DownStreamBackchannelLogoutResponse downStreamBackchannelLogoutResponse =
                    new BackchannelLogoutResponse.DownStreamBackchannelLogoutResponse();
            downStreamBackchannelLogoutResponse.setWithBackchannelLogoutUrl(backchannelLogoutUrl != null);

            if (clientSessionLogoutResponse != null) {
                downStreamBackchannelLogoutResponse.setResponseCode(clientSessionLogoutResponse.getStatus());
            } else {
                downStreamBackchannelLogoutResponse.setResponseCode(null);
            }
            backchannelLogoutResponse.addClientResponses(downStreamBackchannelLogoutResponse);
        }
        if (logoutBroker) {
            String brokerId = userSession.getNote(Details.IDENTITY_PROVIDER);
            if (brokerId != null) {
                IdentityProvider identityProvider = null;
                try {
                    identityProvider = IdentityBrokerService.getIdentityProvider(session, brokerId);
                } catch (IdentityBrokerException e) {
                    logger.warn("Skipping backchannel logout for broker " + brokerId + " - not found");
                }
                if (identityProvider != null) {
                    try {
                        identityProvider.backchannelLogout(session, userSession, uriInfo, realm);
                    } catch (Exception e) {
                        logger.warn("Exception at broker backchannel logout for broker " + brokerId, e);
                        backchannelLogoutResponse.setLocalLogoutSucceeded(false);
                    }
                }
            }
        }

        return backchannelLogoutResponse;
    }

    private static boolean checkUserSessionOnlyHasLoggedOutClients(RealmModel realm,
      UserSessionModel userSession, AuthenticationSessionModel logoutAuthSession) {
        final Map<String, AuthenticatedClientSessionModel> acs = userSession.getAuthenticatedClientSessions();
        Set<AuthenticatedClientSessionModel> notLoggedOutSessions = acs.entrySet().stream()
          .filter(me -> ! Objects.equals(AuthenticationSessionModel.Action.LOGGED_OUT, getClientLogoutAction(logoutAuthSession, me.getKey())))
          .filter(me -> ! Objects.equals(AuthenticationSessionModel.Action.LOGGED_OUT.name(), me.getValue().getAction()))
          .filter(me -> ! Objects.equals(AuthenticationSessionModel.Action.LOGGING_OUT.name(), me.getValue().getAction()))
          .filter(me -> Objects.nonNull(me.getValue().getProtocol()))   // Keycloak service-like accounts
          .map(Map.Entry::getValue)
          .collect(Collectors.toSet());

        boolean allClientsLoggedOut = notLoggedOutSessions.isEmpty();

        if (! allClientsLoggedOut) {
            logger.warnf("Some clients have not been logged out for user %s in %s realm: %s",
              userSession.getUser().getUsername(), realm.getName(),
              notLoggedOutSessions.stream()
                .map(AuthenticatedClientSessionModel::getClient)
                .map(ClientModel::getClientId)
                .sorted()
                .collect(Collectors.joining(", "))
            );
        } else if (logger.isDebugEnabled()) {
            logger.debugf("All clients have been logged out for user %s in %s realm, session %s",
              userSession.getUser().getUsername(), realm.getName(), userSession.getId());
        }

        return allClientsLoggedOut;
    }

    private static Response backchannelLogoutClientSession(KeycloakSession session, RealmModel realm,
            AuthenticatedClientSessionModel clientSession, AuthenticationSessionModel logoutAuthSession,
            UriInfo uriInfo, HttpHeaders headers) {
        UserSessionModel userSession = clientSession.getUserSession();
        ClientModel client = clientSession.getClient();

        if (client.isFrontchannelLogout()
                || AuthenticationSessionModel.Action.LOGGED_OUT.name().equals(clientSession.getAction())) {
            return null;
        }

        final AuthenticationSessionModel.Action logoutState = getClientLogoutAction(logoutAuthSession, client.getId());

        if (logoutState == AuthenticationSessionModel.Action.LOGGED_OUT
                || logoutState == AuthenticationSessionModel.Action.LOGGING_OUT) {
            return Response.ok().build();
        }

        if (!client.isEnabled()) {
            return null;
        }

        try {
            setClientLogoutAction(logoutAuthSession, client.getId(), AuthenticationSessionModel.Action.LOGGING_OUT);

            String authMethod = clientSession.getProtocol();
            if (authMethod == null) return Response.ok().build(); // must be a keycloak service like account

            logger.debugv("backchannel logout to: {0}", client.getClientId());
            LoginProtocol protocol = session.getProvider(LoginProtocol.class, authMethod);
            protocol.setRealm(realm)
                    .setHttpHeaders(headers)
                    .setUriInfo(uriInfo);

            Response clientSessionLogout = protocol.backchannelLogout(userSession, clientSession);

            setClientLogoutAction(logoutAuthSession, client.getId(), AuthenticationSessionModel.Action.LOGGED_OUT);

            return clientSessionLogout;
        } catch (Exception ex) {
            ServicesLogger.LOGGER.failedToLogoutClient(ex);
            return Response.serverError().build();
        }
    }

    public static Response frontchannelLogoutClientSession(KeycloakSession session, RealmModel realm,
      AuthenticatedClientSessionModel clientSession, AuthenticationSessionModel logoutAuthSession,
      UriInfo uriInfo, HttpHeaders headers, EventBuilder event) {
        UserSessionModel userSession = clientSession.getUserSession();
        ClientModel client = clientSession.getClient();

        if (!client.isFrontchannelLogout() || AuthenticationSessionModel.Action.LOGGED_OUT.name().equals(clientSession.getAction())) {
            return null;
        }

        final AuthenticationSessionModel.Action logoutState = getClientLogoutAction(logoutAuthSession, client.getId());

        if (logoutState == AuthenticationSessionModel.Action.LOGGED_OUT || logoutState == AuthenticationSessionModel.Action.LOGGING_OUT) {
            return null;
        }

        try {
            session.clientPolicy().triggerOnEvent(new LogoutRequestContext());
        } catch (ClientPolicyException cpe) {
            event.event(EventType.LOGOUT);
            event.detail(Details.REASON, Details.CLIENT_POLICY_ERROR);
            event.detail(Details.CLIENT_POLICY_ERROR, cpe.getError());
            event.detail(Details.CLIENT_POLICY_ERROR_DETAIL, cpe.getErrorDetail());
            event.error(cpe.getError());
            throw new ErrorResponseException(cpe.getError(), cpe.getErrorDetail(), cpe.getErrorStatus());
        }

        try {
            setClientLogoutAction(logoutAuthSession, client.getId(), AuthenticationSessionModel.Action.LOGGING_OUT);

            String authMethod = clientSession.getProtocol();
            if (authMethod == null) return null; // must be a keycloak service like account

            logger.debugv("frontchannel logout to: {0}", client.getClientId());
            LoginProtocol protocol = session.getProvider(LoginProtocol.class, authMethod);
            protocol.setRealm(realm)
                    .setHttpHeaders(headers)
                    .setUriInfo(uriInfo);

            Response response = protocol.frontchannelLogout(userSession, clientSession);
            if (response != null) {
                logger.debug("returning frontchannel logout request to client");
                // setting this to logged out cuz I'm not sure protocols can always verify that the client was logged out or not

                if (!AuthenticationSessionModel.Action.LOGGING_OUT.name().equals(clientSession.getAction())) {
                    setClientLogoutAction(logoutAuthSession, client.getId(), AuthenticationSessionModel.Action.LOGGED_OUT);
                }

                return response;
            }
        } catch (Exception e) {
            ServicesLogger.LOGGER.failedToLogoutClient(e);
        }

        return null;
    }

    public static void setClientLogoutAction(AuthenticationSessionModel logoutAuthSession, String clientUuid, AuthenticationSessionModel.Action action) {
        if (logoutAuthSession != null && clientUuid != null) {
            logoutAuthSession.setAuthNote(CLIENT_LOGOUT_STATE + clientUuid, action.name());
        }
    }

    public static AuthenticationSessionModel.Action getClientLogoutAction(AuthenticationSessionModel logoutAuthSession, String clientUuid) {
        if (logoutAuthSession == null || clientUuid == null) {
            return null;
        }

        String state = logoutAuthSession.getAuthNote(CLIENT_LOGOUT_STATE + clientUuid);
        return state == null ? null : AuthenticationSessionModel.Action.valueOf(state);
    }

    public static void backchannelLogoutUserFromClient(KeycloakSession session, RealmModel realm, UserModel user, ClientModel client, UriInfo uriInfo, HttpHeaders headers) {
        session.sessions().getUserSessionsStream(realm, user)
                .map(userSession -> userSession.getAuthenticatedClientSessionByClient(client.getId()))
                .filter(Objects::nonNull)
                .collect(Collectors.toList()) // collect to avoid concurrent modification.
                .forEach(clientSession -> {
                    backchannelLogoutClientSession(session, realm, clientSession, null, uriInfo, headers);
                    clientSession.setAction(AuthenticationSessionModel.Action.LOGGED_OUT.name());
                    TokenManager.dettachClientSession(clientSession);
                });
    }

    public static Response browserLogout(KeycloakSession session,
                                         RealmModel realm,
                                         UserSessionModel userSession,
                                         UriInfo uriInfo,
                                         ClientConnection connection,
                                         HttpHeaders headers) {
        if (userSession == null) return null;

        if (logger.isDebugEnabled()) {
            UserModel user = userSession.getUser();
            logger.debugv("Logging out: {0} ({1})", user.getUsername(), userSession.getId());
        }

        if (userSession.getState() != UserSessionModel.State.LOGGING_OUT) {
            userSession.setState(UserSessionModel.State.LOGGING_OUT);
        }

        final AuthenticationSessionManager asm = new AuthenticationSessionManager(session);
        AuthenticationSessionModel logoutAuthSession = createOrJoinLogoutSession(session, realm, asm, userSession, true, false);

        String brokerId = userSession.getNote(Details.IDENTITY_PROVIDER);
        String initiatingIdp = logoutAuthSession.getAuthNote(AuthenticationManager.LOGOUT_INITIATING_IDP);
        if (brokerId != null && !brokerId.equals(initiatingIdp)) {
            IdentityProvider identityProvider = IdentityBrokerService.getIdentityProvider(session, brokerId);
            Response response = identityProvider.keycloakInitiatedBrowserLogout(session, userSession, uriInfo, realm);
            if (response != null) {
                return response;
            }
        }

        return finishBrowserLogout(session, realm, userSession, uriInfo, connection, headers);
    }

    public static Response browserLogoutAllClients(UserSessionModel userSession, KeycloakSession session, RealmModel realm, HttpHeaders headers, UriInfo uriInfo, AuthenticationSessionModel logoutAuthSession, EventBuilder event) {
        Map<Boolean, List<AuthenticatedClientSessionModel>> acss = userSession.getAuthenticatedClientSessions().values().stream()
          .filter(clientSession -> !Objects.equals(AuthenticationSessionModel.Action.LOGGED_OUT.name(), clientSession.getAction())
                                && !Objects.equals(AuthenticationSessionModel.Action.LOGGING_OUT.name(), clientSession.getAction()))
          .filter(clientSession -> clientSession.getProtocol() != null)
          .collect(Collectors.partitioningBy(clientSession -> clientSession.getClient().isFrontchannelLogout()));

        final List<AuthenticatedClientSessionModel> backendLogoutSessions = acss.get(false) == null ? Collections.emptyList() : acss.get(false);
        backendLogoutSessions.forEach(acs -> backchannelLogoutClientSession(session, realm, acs, logoutAuthSession, uriInfo, headers));

        final List<AuthenticatedClientSessionModel> redirectClients = acss.get(true) == null ? Collections.emptyList() : acss.get(true);
        for (AuthenticatedClientSessionModel nextRedirectClient : redirectClients) {
            Response response = frontchannelLogoutClientSession(session, realm, nextRedirectClient, logoutAuthSession, uriInfo, headers, event);
            if (response != null) {
                return response;
            }
        }

        return null;
    }

    public static Response finishBrowserLogout(KeycloakSession session, RealmModel realm, UserSessionModel userSession, UriInfo uriInfo, ClientConnection connection, HttpHeaders headers) {
        final AuthenticationSessionManager asm = new AuthenticationSessionManager(session);
        AuthenticationSessionModel logoutAuthSession = createOrJoinLogoutSession(session, realm, asm, userSession, true, false);
        EventBuilder event = new EventBuilder(realm, session, connection);
        Response response = browserLogoutAllClients(userSession, session, realm, headers, uriInfo, logoutAuthSession, event);
        if (response != null) {
            return response;
        }

        checkUserSessionOnlyHasLoggedOutClients(realm, userSession, logoutAuthSession);

        // For resolving artifact we don't need any cookie, all details are stored in session storage so we can remove
        expireIdentityCookie(session);
        expireRememberMeCookie(session);

        String method = userSession.getNote(KEYCLOAK_LOGOUT_PROTOCOL);
        LoginProtocol protocol = session.getProvider(LoginProtocol.class, method);
        protocol.setRealm(realm)
                .setHttpHeaders(headers)
                .setUriInfo(uriInfo)
                .setEventBuilder(event);

        response = protocol.finishBrowserLogout(userSession, logoutAuthSession);

        // It may be possible that there are some client sessions that are still in LOGGING_OUT state
        long numberOfUnconfirmedSessions = userSession.getAuthenticatedClientSessions().values().stream()
                .filter(clientSessionModel -> CommonClientSessionModel.Action.LOGGING_OUT.name().equals(clientSessionModel.getAction()))
                .count();

        // If logout flow end up correctly there should be at maximum 1 client session in LOGGING_OUT action, if there are more, something went wrong
        if (numberOfUnconfirmedSessions > 1) {
            logger.warnf("There are more than one clientSession in logging_out state. Perhaps some client did not finish logout flow correctly.");
        }

        // By setting LOGGED_OUT_UNCONFIRMED state we are saying that anybody who will turn the last client session into
        // LOGGED_OUT action can remove UserSession
        if (numberOfUnconfirmedSessions >= 1) {
            userSession.setState(UserSessionModel.State.LOGGED_OUT_UNCONFIRMED);
        } else {
            userSession.setState(UserSessionModel.State.LOGGED_OUT);
        }

        // Do not remove user session, it will be removed when last clientSession will be logged out
        if (numberOfUnconfirmedSessions < 1) {
            session.sessions().removeUserSession(realm, userSession);
        }

        logger.tracef("Removing logout session '%s'.", logoutAuthSession.getParentSession().getId());
        session.authenticationSessions().removeRootAuthenticationSession(realm, logoutAuthSession.getParentSession());

        return response;
    }

    public static void finishUnconfirmedUserSession(KeycloakSession session, RealmModel realm, UserSessionModel userSessionModel) {
        if (userSessionModel.getAuthenticatedClientSessions().values().stream().anyMatch(cs -> !CommonClientSessionModel.Action.LOGGED_OUT.name().equals(cs.getAction()))) {
            logger.warnf("UserSession with id %s is removed while there are still some user sessions that are not logged out properly.", userSessionModel.getId());
            if (logger.isTraceEnabled()) {
                logger.trace("Client sessions with their states:");
                userSessionModel.getAuthenticatedClientSessions().values()
                        .forEach(clientSessionModel -> logger.tracef("Client session for clientId: %s has action: %s", clientSessionModel.getClient().getClientId(), clientSessionModel.getAction()));
            }
        }

        session.sessions().removeUserSession(realm, userSessionModel);
    }
}