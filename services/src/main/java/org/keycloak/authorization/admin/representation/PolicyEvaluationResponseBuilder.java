/*
 * Copyright 2022 Scott Weeden and/or his affiliates
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
package org.keycloak.authorization.admin.representation;

import org.keycloak.authorization.fgap.AdminPermissionsSchema;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.Decision;
import org.keycloak.authorization.admin.PolicyEvaluationService.EvaluationDecisionCollector;
import org.keycloak.authorization.common.KeycloakIdentity;
import org.keycloak.authorization.model.PermissionTicket;
import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.model.Scope;
import org.keycloak.authorization.policy.evaluation.Result;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.authorization.DecisionEffect;
import org.keycloak.representations.idm.authorization.PolicyEvaluationRequest;
import org.keycloak.representations.idm.authorization.PolicyEvaluationResponse;
import org.keycloak.representations.idm.authorization.PolicyEvaluationResponse.PolicyResultRepresentation;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class PolicyEvaluationResponseBuilder {
    public static PolicyEvaluationResponse build(EvaluationDecisionCollector decision, ResourceServer resourceServer, AuthorizationProvider authorization, KeycloakIdentity identity, PolicyEvaluationRequest request) {
        if (AdminPermissionsSchema.SCHEMA.isAdminPermissionClient(authorization.getRealm(), resourceServer.getId())) {
            return FGAPPolicyEvaluationResponseBuilder.build(decision, resourceServer, authorization, request);
        }

        PolicyEvaluationResponse response = new PolicyEvaluationResponse();
        List<PolicyEvaluationResponse.EvaluationResultRepresentation> resultsRep = new ArrayList<>();
        AccessToken accessToken = identity.getAccessToken();
        AccessToken.Authorization authorizationData = new AccessToken.Authorization();

        authorizationData.setPermissions(decision.results());
        accessToken.setAuthorization(authorizationData);

        ClientModel clientModel = authorization.getRealm().getClientById(resourceServer.getClientId());

        if (!accessToken.hasAudience(clientModel.getClientId())) {
            accessToken.audience(clientModel.getClientId());
        }

        response.setRpt(accessToken);

        Collection<Result> results = decision.getResults();

        if (results.stream().anyMatch(evaluationResult -> evaluationResult.getEffect().equals(Decision.Effect.DENY))) {
            response.setStatus(DecisionEffect.DENY);
        } else {
            response.setStatus(DecisionEffect.PERMIT);
        }

        for (Result result : results) {
            PolicyEvaluationResponse.EvaluationResultRepresentation rep = new PolicyEvaluationResponse.EvaluationResultRepresentation();

            if (result.getEffect() == Decision.Effect.DENY) {
                rep.setStatus(DecisionEffect.DENY);
            } else {
                rep.setStatus(DecisionEffect.PERMIT);

            }
            resultsRep.add(rep);

            if (result.getPermission().getResource() != null) {
                ResourceRepresentation resource = new ResourceRepresentation();

                resource.setId(result.getPermission().getResource().getId());
                resource.setName(result.getPermission().getResource().getName());

                rep.setResource(resource);
            } else {
                ResourceRepresentation resource = new ResourceRepresentation();

                resource.setName("Any Resource with Scopes " + result.getPermission().getScopes().stream().map(Scope::getName).collect(Collectors.toList()));

                rep.setResource(resource);
            }

            rep.setScopes(result.getPermission().getScopes().stream().map(scope -> {
                ScopeRepresentation representation = new ScopeRepresentation();

                representation.setId(scope.getId());
                representation.setName(scope.getName());

                return representation;
            }).collect(Collectors.toList()));

            Set<PolicyEvaluationResponse.PolicyResultRepresentation> policies = new HashSet<>();

            for (Result.PolicyResult policy : result.getResults()) {
                PolicyResultRepresentation policyRep = toRepresentation(policy, authorization);

                if ("resource".equals(policy.getPolicy().getType())) {
                    policyRep.getPolicy().setScopes(result.getPermission().getResource().getScopes().stream().map(Scope::getName).collect(Collectors.toSet()));
                }

                policies.add(policyRep);
            }

            rep.setPolicies(policies);
        }

        resultsRep.sort(Comparator.comparing(o -> o.getResource().getName()));

        Map<String, PolicyEvaluationResponse.EvaluationResultRepresentation> groupedResults = new HashMap<>();

        resultsRep.forEach(evaluationResultRepresentation -> {
            PolicyEvaluationResponse.EvaluationResultRepresentation result = groupedResults.get(evaluationResultRepresentation.getResource().getId());
            ResourceRepresentation resource = evaluationResultRepresentation.getResource();

            if (result == null) {
                groupedResults.put(resource.getId(), evaluationResultRepresentation);
                result = evaluationResultRepresentation;
            }

            if (result.getStatus().equals(DecisionEffect.PERMIT) || (evaluationResultRepresentation.getStatus().equals(DecisionEffect.PERMIT) && result.getStatus().equals(DecisionEffect.DENY))) {
                result.setStatus(DecisionEffect.PERMIT);
            }

            List<ScopeRepresentation> scopes = result.getScopes();

            if (DecisionEffect.PERMIT.equals(result.getStatus())) {
                result.setAllowedScopes(new HashSet<>(scopes));
            }

            if (resource.getId() != null) {
                if (!scopes.isEmpty()) {
                    result.getResource().setName(evaluationResultRepresentation.getResource().getName() + " with scopes " + scopes.stream().flatMap((Function<ScopeRepresentation, Stream<?>>) scopeRepresentation -> Stream.of(scopeRepresentation.getName())).toList());
                } else {
                    result.getResource().setName(evaluationResultRepresentation.getResource().getName());
                }
            } else {
                result.getResource().setName("Any Resource with Scopes " + scopes.stream().flatMap((Function<ScopeRepresentation, Stream<?>>) scopeRepresentation -> Stream.of(scopeRepresentation.getName())).toList());
            }

            result.getPolicies().addAll(evaluationResultRepresentation.getPolicies());
        });

        response.setResults(new ArrayList<>(groupedResults.values()));

        return response;
    }

    private static PolicyEvaluationResponse.PolicyResultRepresentation toRepresentation(Result.PolicyResult result, AuthorizationProvider authorization) {
        PolicyEvaluationResponse.PolicyResultRepresentation policyResultRep = new PolicyEvaluationResponse.PolicyResultRepresentation();

        PolicyRepresentation representation = new PolicyRepresentation();
        Policy policy = result.getPolicy();
        ResourceServer resourceServer = policy.getResourceServer();

        representation.setId(policy.getId());
        representation.setName(policy.getName());
        representation.setType(policy.getType());
        representation.setDecisionStrategy(policy.getDecisionStrategy());
        representation.setDescription(policy.getDescription());

        if ("uma".equals(representation.getType())) {
            Map<PermissionTicket.FilterOption, String> filters = new EnumMap<>(PermissionTicket.FilterOption.class);

            filters.put(PermissionTicket.FilterOption.POLICY_ID, policy.getId());

            List<PermissionTicket> tickets = authorization.getStoreFactory().getPermissionTicketStore().find(resourceServer, filters, -1, 1);

            if (!tickets.isEmpty()) {
                KeycloakSession keycloakSession = authorization.getKeycloakSession();
                RealmModel realm = authorization.getRealm();
                PermissionTicket ticket = tickets.get(0);
                UserModel userOwner = keycloakSession.users().getUserById(realm, ticket.getOwner());
                UserModel requester = keycloakSession.users().getUserById(realm, ticket.getRequester());
                String resourceOwner;
                if (userOwner != null) {
                    resourceOwner = getUserEmailOrUserName(userOwner);
                } else {
                    ClientModel clientOwner = realm.getClientById(ticket.getOwner());
                    resourceOwner = clientOwner.getClientId();
                }

                representation.setDescription("Resource owner (" + resourceOwner + ") grants access to " + getUserEmailOrUserName(requester));
            } else {
                String description = representation.getDescription();

                if (description != null) {
                    representation.setDescription(description + " (User-Managed Policy)");
                } else {
                    representation.setDescription("User-Managed Policy");
                }
            }
        }

        representation.setResources(policy.getResources().stream().map(resource -> resource.getName()).collect(Collectors.toSet()));

        Set<String> scopeNames = policy.getScopes().stream().map(scope -> scope.getName()).collect(Collectors.toSet());

        representation.setScopes(scopeNames);

        policyResultRep.setPolicy(representation);

        if (result.getEffect() == Decision.Effect.DENY) {
            policyResultRep.setStatus(DecisionEffect.DENY);
            policyResultRep.setScopes(representation.getScopes());
        } else {
            policyResultRep.setStatus(DecisionEffect.PERMIT);
        }

        policyResultRep.setAssociatedPolicies(result.getAssociatedPolicies().stream().map(policy1 -> toRepresentation(policy1, authorization)).collect(Collectors.toList()));

        return policyResultRep;
    }

    private static String getUserEmailOrUserName(UserModel user) {
        return (user.getEmail() != null ? user.getEmail() : user.getUsername());
    }
}
