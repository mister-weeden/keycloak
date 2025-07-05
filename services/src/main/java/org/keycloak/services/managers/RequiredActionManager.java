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
package org.keycloak.services.managers;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionContextResult;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionProviderModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.DefaultRequiredActions;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.sessions.AuthenticationSessionModel;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import java.net.URI;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Handles required action operations extracted from AuthenticationManager
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 */
public class RequiredActionManager {
    
    private static final Logger logger = Logger.getLogger(RequiredActionManager.class);

    public static String nextRequiredAction(final KeycloakSession session, final AuthenticationSessionModel authSession,
            final HttpRequest request, final EventBuilder event) {
        final var realm = authSession.getRealm();
        final var user = authSession.getAuthenticatedUser();

        evaluateRequiredActionTriggers(session, authSession, request, event, realm, user, new HashSet<>());

        final var kcAction = authSession.getClientNote(Constants.KC_ACTION);
        final var nextApplicableAction =
                getFirstApplicableRequiredAction(realm, authSession, user, kcAction, new HashSet<>());
        if (nextApplicableAction != null) {
            return nextApplicableAction.getAlias();
        }

        return null;
    }

    public static Response redirectToRequiredActions(KeycloakSession session, RealmModel realm, AuthenticationSessionModel authSession, UriInfo uriInfo, String requiredAction) {
        // redirect to non-action url so browser refresh button works without reposting past data
        ClientSessionCode<AuthenticationSessionModel> accessCode = new ClientSessionCode<>(session, realm, authSession);
        accessCode.setAction(AuthenticationSessionModel.Action.REQUIRED_ACTIONS.name());
        authSession.setAuthNote(AuthenticationProcessor.CURRENT_FLOW_PATH, LoginActionsService.REQUIRED_ACTION);
        authSession.setAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION, requiredAction);

        UriBuilder uriBuilder = LoginActionsService.loginActionsBaseUrl(uriInfo)
                .path(LoginActionsService.REQUIRED_ACTION);

        if (requiredAction != null) {
            uriBuilder.queryParam(Constants.EXECUTION, requiredAction);
        }

        uriBuilder.queryParam(Constants.CLIENT_ID, authSession.getClient().getClientId());
        uriBuilder.queryParam(Constants.TAB_ID, authSession.getTabId());
        uriBuilder.queryParam(Constants.CLIENT_DATA, AuthenticationProcessor.getClientData(session, authSession));

        if (uriInfo.getQueryParameters().containsKey(LoginActionsService.AUTH_SESSION_ID)) {
            uriBuilder.queryParam(LoginActionsService.AUTH_SESSION_ID, authSession.getParentSession().getId());

        }

        URI redirect = uriBuilder.build(realm.getName());
        return Response.status(302).location(redirect).build();
    }

    public static Response executionActions(KeycloakSession session, AuthenticationSessionModel authSession,
            HttpRequest request, EventBuilder event, RealmModel realm, UserModel user, Set<String> ignoredActions) {
        final String kcAction = authSession.getClientNote(Constants.KC_ACTION);
        final RequiredActionProviderModel firstApplicableRequiredAction =
                getFirstApplicableRequiredAction(realm, authSession, user, kcAction, ignoredActions);
        boolean kcActionExecution = kcAction != null && kcAction.equals(firstApplicableRequiredAction.getProviderId());

        if (firstApplicableRequiredAction != null) {
            return executeAction(session, authSession, firstApplicableRequiredAction, request, event, realm, user,
                    kcActionExecution, ignoredActions);
        }

        return null;
    }

    private static Response executeAction(KeycloakSession session, AuthenticationSessionModel authSession, RequiredActionProviderModel model,
                                          HttpRequest request, EventBuilder event, RealmModel realm, UserModel user, boolean kcActionExecution,
                                          Set<String> ignoredActions) {
        RequiredActionFactory factory = (RequiredActionFactory) session.getKeycloakSessionFactory()
                .getProviderFactory(RequiredActionProvider.class, model.getProviderId());
        if (factory == null) {
            throw new RuntimeException("Unable to find factory for Required Action: " + model.getProviderId() + " did you forget to declare it in a META-INF/services file?");
        }
        RequiredActionContextResult context = new RequiredActionContextResult(authSession, realm, event, session, request, user, factory);
        RequiredActionProvider actionProvider = null;
        try {
            actionProvider = createRequiredAction(context);
        } catch (AuthenticationFlowException e) {
            if (e.getResponse() != null) {
                return e.getResponse();
            }
            throw e;
        }

        if (kcActionExecution) {
            if (actionProvider.initiatedActionSupport() == InitiatedActionSupport.NOT_SUPPORTED) {
                logger.debugv("Requested action {0} does not support being invoked with kc_action", factory.getId());
                setKcActionStatus(factory.getId(), RequiredActionContext.KcActionStatus.ERROR, authSession);
                ignoredActions.add(factory.getId());
                return null;
            } else if (!model.isEnabled()) {
                logger.debugv("Requested action {0} is disabled and can't be invoked with kc_action", factory.getId());
                setKcActionStatus(factory.getId(), RequiredActionContext.KcActionStatus.ERROR, authSession);
                ignoredActions.add(factory.getId());
                return null;
            } else {
                authSession.setClientNote(Constants.KC_ACTION_EXECUTING, factory.getId());
            }
        }

        actionProvider.requiredActionChallenge(context);

        if (context.getStatus() == RequiredActionContext.Status.FAILURE) {
            LoginProtocol protocol = context.getSession().getProvider(LoginProtocol.class, context.getAuthenticationSession().getProtocol());
            protocol.setRealm(context.getRealm())
                    .setHttpHeaders(context.getHttpRequest().getHttpHeaders())
                    .setUriInfo(context.getUriInfo())
                    .setEventBuilder(event);
            Response response = protocol.sendError(context.getAuthenticationSession(), LoginProtocol.Error.CONSENT_DENIED, null);
            event.error(Errors.REJECTED_BY_USER);
            return response;
        }
        else if (context.getStatus() == RequiredActionContext.Status.CHALLENGE) {
            authSession.setAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION, model.getProviderId());
            return context.getChallenge();
        }
        else if (context.getStatus() == RequiredActionContext.Status.IGNORE) {
            setKcActionStatus(factory.getId(), RequiredActionContext.KcActionStatus.ERROR, authSession);
            ignoredActions.add(factory.getId());
            return null;
        }
        else if (context.getStatus() == RequiredActionContext.Status.SUCCESS) {
            event.clone().event(EventType.CUSTOM_REQUIRED_ACTION).detail(Details.CUSTOM_REQUIRED_ACTION, factory.getId()).success();
            // don't have to perform the same action twice, so remove it from both the user and session required actions
            authSession.getAuthenticatedUser().removeRequiredAction(factory.getId());
            authSession.removeRequiredAction(factory.getId());
            setKcActionStatus(factory.getId(), RequiredActionContext.KcActionStatus.SUCCESS, authSession);
            return null;
        }

        return null;
    }

    public static RequiredActionProvider createRequiredAction(RequiredActionContextResult context) {
        return context.getFactory().create(context.getSession());
    }

    public static void evaluateRequiredActionTriggers(final KeycloakSession session, final AuthenticationSessionModel authSession,
                                                      final HttpRequest request, final EventBuilder event,
                                                      final RealmModel realm, final UserModel user) {
        evaluateRequiredActionTriggers(session, authSession, request, event, realm, user, new HashSet<>());
    }

    private static void evaluateRequiredActionTriggers(final KeycloakSession session, final AuthenticationSessionModel authSession,
                                                      final HttpRequest request, final EventBuilder event,
                                                      final RealmModel realm, final UserModel user, Set<String> ignoredActions) {
        // see if any required actions need triggering, i.e. an expired password
        realm.getRequiredActionProvidersStream()
                .filter(RequiredActionProviderModel::isEnabled)
                .filter(model -> !ignoredActions.contains(model.getProviderId()))
                .map(model -> toRequiredActionFactory(session, model, realm))
                .filter(Objects::nonNull)
                .forEachOrdered(f -> evaluateRequiredAction(session, authSession, request, event, realm, user, f));
    }

    private static void evaluateRequiredAction(final KeycloakSession session, final AuthenticationSessionModel authSession,
                                        final HttpRequest request, final EventBuilder event, final RealmModel realm,
                                        final UserModel user, RequiredActionFactory factory) {
        RequiredActionProvider provider = factory.create(session);
        RequiredActionContextResult result = new RequiredActionContextResult(authSession, realm, event, session, request, user, factory) {
            @Override
            public void challenge(Response response) {
                throw new RuntimeException("Not allowed to call challenge() within evaluateTriggers()");
            }

            @Override
            public void failure() {
                throw new RuntimeException("Not allowed to call failure() within evaluateTriggers()");
            }

            @Override
            public void success() {
                throw new RuntimeException("Not allowed to call success() within evaluateTriggers()");
            }

            @Override
            public void cancel() {
                throw new RuntimeException("Not allowed to call cancel() within evaluateTriggers()");
            }

            @Override
            public void ignore() {
                throw new RuntimeException("Not allowed to call ignore() within evaluateTriggers()");
            }
        };

        provider.evaluateTriggers(result);
    }

    private static RequiredActionProviderModel getFirstApplicableRequiredAction(final RealmModel realm,
            final AuthenticationSessionModel authSession, final UserModel user, final String kcAction, final Set<String> ignoredActions) {
        final var applicableRequiredActionsSorted =
                getApplicableRequiredActionsSorted(realm, authSession, user, kcAction, ignoredActions);

        final RequiredActionProviderModel firstApplicableRequiredAction;
        if (applicableRequiredActionsSorted.isEmpty()) {
            firstApplicableRequiredAction = null;
            logger.debugv("Did not find applicable required action");
        } else {
            firstApplicableRequiredAction = applicableRequiredActionsSorted.iterator().next();
            logger.debugv("first applicable required action: {0}", firstApplicableRequiredAction.getAlias());
        }

        return firstApplicableRequiredAction;
    }

    private static List<RequiredActionProviderModel> getApplicableRequiredActionsSorted(final RealmModel realm,
            final AuthenticationSessionModel authSession, final UserModel user, final String kcActionAlias, final Set<String> ignoredActions) {
        final Set<String> nonInitiatedActionAliases = new HashSet<>();
        nonInitiatedActionAliases.addAll(user.getRequiredActionsStream().toList());
        nonInitiatedActionAliases.addAll(authSession.getRequiredActions());

        final Map<String, RequiredActionProviderModel> applicableNonInitiatedActions = nonInitiatedActionAliases.stream()
                .map(alias -> getApplicableRequiredAction(realm, alias))
                .filter(Objects::nonNull)
                .filter(model -> !ignoredActions.contains(model.getProviderId()))
                .collect(Collectors.toMap(RequiredActionProviderModel::getAlias, Function.identity()));

        RequiredActionProviderModel kcAction = null;
        if (kcActionAlias != null) {
            kcAction = getApplicableRequiredAction(realm, kcActionAlias);
            if (kcAction == null) {
                logger.debugv("Requested action {0} not configured for realm", kcActionAlias);
                setKcActionStatus(kcActionAlias, RequiredActionContext.KcActionStatus.ERROR, authSession);
            } else {
                if (applicableNonInitiatedActions.containsKey(kcActionAlias)) {
                    setKcActionToEnforced(kcActionAlias, authSession);
                }
            }
        }

        final List<RequiredActionProviderModel> applicableActionsSorted = applicableNonInitiatedActions.values().stream()
                .sorted(RequiredActionProviderModel.RequiredActionComparator.SINGLETON)
                .collect(Collectors.toList());

        // Insert "kc_action" as last action (unless present in required actions)
        if (kcAction != null && !applicableNonInitiatedActions.containsKey(kcActionAlias)) {
            applicableActionsSorted.add(kcAction);
        }

        if (logger.isDebugEnabled()) {
            logger.debugv("applicable required actions (sorted): {0}",
                    applicableActionsSorted.stream().map(RequiredActionProviderModel::getAlias).toList());
        }

        return applicableActionsSorted;
    }

    private static RequiredActionProviderModel getApplicableRequiredAction(final RealmModel realm, final String alias) {
        final var model = realm.getRequiredActionProviderByAlias(alias);
        if (model == null) {
            logger.warnv(
                    "Could not find configuration for Required Action {0}, did you forget to register it?",
                    alias);
            return null;
        }

        if (!model.isEnabled()) {
            return null;
        }

        return model;
    }

    private static RequiredActionFactory toRequiredActionFactory(KeycloakSession session, RequiredActionProviderModel model, RealmModel realm) {
        RequiredActionFactory factory = (RequiredActionFactory) session.getKeycloakSessionFactory()
                .getProviderFactory(RequiredActionProvider.class, model.getProviderId());
        if (factory == null) {
            if (!DefaultRequiredActions.isActionAvailable(model)) {
                logger.warnf("Required action provider factory '%s' configured in the realm '%s' is not available. " +
                        "Provider not found or feature is disabled.", model.getProviderId(), realm.getName());
            } else {
                throw new RuntimeException(String.format("Unable to find factory for Required Action '%s' configured in the realm '%s'. " +
                        "Did you forget to declare it in a META-INF/services file?", model.getProviderId(), realm.getName()));
            }
        }
        return factory;
    }

    public static void setKcActionStatus(String executedProviderId, RequiredActionContext.KcActionStatus status, AuthenticationSessionModel authSession) {
        if (executedProviderId.equals(authSession.getClientNote(Constants.KC_ACTION))) {
            authSession.setClientNote(Constants.KC_ACTION_STATUS, status.name().toLowerCase());
            authSession.removeClientNote(Constants.KC_ACTION);
            authSession.removeClientNote(Constants.KC_ACTION_EXECUTING);
        }
    }

    public static void setKcActionToEnforced(String executedProviderId, AuthenticationSessionModel authSession) {
        if (executedProviderId.equals(authSession.getClientNote(Constants.KC_ACTION))) {
            authSession.setClientNote(Constants.KC_ACTION_ENFORCED, Boolean.TRUE.toString());
        }
    }
}