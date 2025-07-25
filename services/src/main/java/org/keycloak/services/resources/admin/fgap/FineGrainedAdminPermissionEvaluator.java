/*
 * Copyright 2025 Scott Weeden and/or his affiliates
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
package org.keycloak.services.resources.admin.fgap;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.keycloak.authorization.fgap.AdminPermissionsSchema;
import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.model.ResourceWrapper;
import org.keycloak.authorization.permission.ResourcePermission;
import org.keycloak.authorization.policy.evaluation.EvaluationContext;
import org.keycloak.authorization.store.PolicyStore;
import org.keycloak.authorization.store.ResourceStore;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.idm.authorization.Permission;

class FineGrainedAdminPermissionEvaluator {
    private final KeycloakSession session;
    private final MgmtPermissions root;
    private final ResourceStore resourceStore;
    private final PolicyStore policyStore;

    FineGrainedAdminPermissionEvaluator(KeycloakSession session, MgmtPermissions root, ResourceStore resourceStore, PolicyStore policyStore) {
        this.session = session;
        this.root = root;
        this.resourceStore = resourceStore;
        this.policyStore = policyStore;
    }

    boolean hasPermission(ModelRecord model, EvaluationContext context, String scope) {
        return hasPermission(model.getId(), model.getResourceType(), context, scope);
    }

    boolean hasPermission(String modelId, String resourceType, EvaluationContext context, String scope) {
        if (!root.isAdminSameRealm()) {
            return false;
        }

        ResourceServer server = root.realmResourceServer();

        if (server == null) {
            return false;
        }

        Resource resourceTypeResource = AdminPermissionsSchema.SCHEMA.getResourceTypeResource(session, server, resourceType);
        Resource resource = modelId == null ? resourceTypeResource : resourceStore.findByName(server, modelId);

        if (modelId != null && resource == null) {
            resource = new ResourceWrapper(modelId, modelId, new HashSet<>(resourceTypeResource.getScopes()), server);
        }

        Collection<Permission> permissions = (context == null) ?
                root.evaluatePermission(new ResourcePermission(resourceType, resource, resource.getScopes(), server), server) :
                root.evaluatePermission(new ResourcePermission(resourceType, resource, resource.getScopes(), server), server, context);

        for (Permission permission : permissions) {
            if (permission.getResourceId().equals(resource.getId())) {
                if (permission.getScopes().contains(scope)) {
                    return true;
                }
            }
        }

        return false;
    }

    Set<String> getIdsByScope(String resourceType, String scope) {
        if (!root.isAdminSameRealm()) {
            return Collections.emptySet();
        }

        ResourceServer server = root.realmResourceServer();

        if (server == null) {
            return Collections.emptySet();
        }

        return policyStore.findByResourceType(server, resourceType).stream()
                .flatMap((Function<Policy, Stream<Resource>>) policy -> policy.getResources().stream())
                .filter(resource -> hasPermission(resource.getName(), resourceType, null, scope))
                .map(Resource::getName)
                .collect(Collectors.toSet());
    }
}
