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
package org.keycloak.testsuite.authz.admin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Collections;
import java.util.stream.Collectors;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;

import jakarta.ws.rs.core.Response.Status;
import org.junit.Test;
import org.keycloak.admin.client.resource.AuthorizationResource;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.PolicyResource;
import org.keycloak.admin.client.resource.RolePoliciesResource;
import org.keycloak.admin.client.resource.RolePolicyResource;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.authorization.DecisionStrategy;
import org.keycloak.representations.idm.authorization.Logic;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;
import org.keycloak.representations.idm.authorization.RolePolicyRepresentation;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.util.RealmBuilder;
import org.keycloak.testsuite.util.RoleBuilder;
import org.keycloak.testsuite.util.RolesBuilder;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class RolePolicyManagementTest extends AbstractPolicyManagementTest {

    @Override
    protected RealmBuilder createTestRealm() {
        return super.createTestRealm().roles(
                RolesBuilder.create()
                        .realmRole(new RoleRepresentation("Role A", "Role A description", false))
                        .realmRole(new RoleRepresentation("Role B", "Role B description", false))
                        .realmRole(new RoleRepresentation("Role C", "Role C description", false))
        );
    }

    @Test
    public void testCreateRealmRolePolicy() {
        AuthorizationResource authorization = getClient().authorization();
        RolePolicyRepresentation representation = new RolePolicyRepresentation();

        representation.setName("Realm Role Policy");
        representation.setDescription("description");
        representation.setDecisionStrategy(DecisionStrategy.CONSENSUS);
        representation.setLogic(Logic.NEGATIVE);
        representation.addRole("Role A", false);
        representation.addRole("Role B", true);

        assertCreated(authorization, representation);
    }

    @Test
    public void testCreateFetchRoles() {
        AuthorizationResource authorization = getClient().authorization();
        RolePolicyRepresentation representation = new RolePolicyRepresentation();

        representation.setName(KeycloakModelUtils.generateId());
        representation.setFetchRoles(true);
        representation.addRole("Role A", false);
        representation.addRole("Role B", true);

        assertCreated(authorization, representation);
    }

    @Test
    public void testCreateClientRolePolicy() {
        ClientResource client = getClient();
        AuthorizationResource authorization = client.authorization();
        RolePolicyRepresentation representation = new RolePolicyRepresentation();

        representation.setName("Realm Client Role Policy");
        representation.setDescription("description");
        representation.setDecisionStrategy(DecisionStrategy.CONSENSUS);
        representation.setLogic(Logic.NEGATIVE);

        RolesResource roles = client.roles();

        roles.create(new RoleRepresentation("Client Role A", "desc", false));

        ClientRepresentation clientRep = client.toRepresentation();

        roles.create(new RoleRepresentation("Client Role B", "desc", false));

        representation.addRole("resource-server-test/Client Role A");
        representation.addClientRole(clientRep.getClientId(), "Client Role B", true);

        assertCreated(authorization, representation);
    }

    @Test
    public void testUpdate() {
        AuthorizationResource authorization = getClient().authorization();
        RolePolicyRepresentation representation = new RolePolicyRepresentation();

        representation.setName("Update Test Role Policy");
        representation.setDescription("description");
        representation.setDecisionStrategy(DecisionStrategy.CONSENSUS);
        representation.setLogic(Logic.NEGATIVE);
        representation.addRole("Role A", false);
        representation.addRole("Role B", true);
        representation.addRole("Role C", false);

        assertCreated(authorization, representation);

        representation.setName("changed");
        representation.setDescription("changed");
        representation.setFetchRoles(true);
        representation.setDecisionStrategy(DecisionStrategy.AFFIRMATIVE);
        representation.setLogic(Logic.POSITIVE);
        representation.setRoles(representation.getRoles().stream().filter(roleDefinition -> !roleDefinition.getId().equals("Resource A")).collect(Collectors.toSet()));

        RolePoliciesResource policies = authorization.policies().role();
        RolePolicyResource permission = policies.findById(representation.getId());

        permission.update(representation);
        assertRepresentation(representation, permission);

        for (RolePolicyRepresentation.RoleDefinition roleDefinition : representation.getRoles()) {
            if (roleDefinition.getId().equals("Role B")) {
                roleDefinition.setRequired(false);
            }
            if (roleDefinition.getId().equals("Role C")) {
                roleDefinition.setRequired(true);
            }
        }

        permission.update(representation);
        assertRepresentation(representation, permission);
    }

    @Test
    public void testDelete() {
        AuthorizationResource authorization = getClient().authorization();
        RolePolicyRepresentation representation = new RolePolicyRepresentation();

        representation.setName("Test Delete Permission");
        representation.addRole("Role A", false);

        RolePoliciesResource policies = authorization.policies().role();

        try (Response response = policies.create(representation)) {
            RolePolicyRepresentation created = response.readEntity(RolePolicyRepresentation.class);

            policies.findById(created.getId()).remove();

            RolePolicyResource removed = policies.findById(created.getId());

            try {
                removed.toRepresentation();
                fail("Permission not removed");
            } catch (NotFoundException ignore) {

            }
        }
    }

    @Test
    public void testDeleteRole() {
        RoleRepresentation role = RoleBuilder.create().name(KeycloakModelUtils.generateId()).build();
        getRealm().roles().create(role);
        AuthorizationResource authorization = getClient().authorization();
        RolePolicyRepresentation representation = new RolePolicyRepresentation();

        representation.setName(KeycloakModelUtils.generateId());
        representation.addRole(role.getName(), false);

        RolePoliciesResource policies = authorization.policies().role();

        try (Response response = policies.create(representation)) {
            RolePolicyRepresentation created = response.readEntity(RolePolicyRepresentation.class);
            RolePolicyResource rolePolicy = policies.findById(created.getId());
            RolePolicyRepresentation rolePolicyRep = rolePolicy.toRepresentation();
            assertEquals(1, rolePolicyRep.getRoles().size());

            getRealm().roles().deleteRole(role.getName());
            rolePolicyRep = rolePolicy.toRepresentation();
            assertTrue(rolePolicyRep.getRoles().isEmpty());
        }
    }

    @Test
    public void testGenericConfig() {
        AuthorizationResource authorization = getClient().authorization();
        RolePolicyRepresentation representation = new RolePolicyRepresentation();

        representation.setName("Test Generic Config  Permission");
        representation.addRole("Role A", false);

        RolePoliciesResource policies = authorization.policies().role();

        try (Response response = policies.create(representation)) {
            RolePolicyRepresentation created = response.readEntity(RolePolicyRepresentation.class);

            PolicyResource policy = authorization.policies().policy(created.getId());
            PolicyRepresentation genericConfig = policy.toRepresentation();

            assertNotNull(genericConfig.getConfig());
            assertNotNull(genericConfig.getConfig().get("roles"));

            RoleRepresentation role = getRealm().roles().get("Role A").toRepresentation();

            assertTrue(genericConfig.getConfig().get("roles").contains(role.getId()));
        }
    }

    @Test
    public void testFailDuplicatedRoles() {
        AuthorizationResource authorization = getClient().authorization();
        RolePolicyRepresentation representation = new RolePolicyRepresentation();

        representation.setName(KeycloakModelUtils.generateId());
        representation.setDescription("description");
        representation.setDecisionStrategy(DecisionStrategy.CONSENSUS);
        representation.setLogic(Logic.NEGATIVE);
        representation.addRole("Role A");
        representation.addRole("Role A");

        try (
            Response response = authorization.policies().role().create(representation);
        ) {
            assertEquals(Status.BAD_REQUEST.getStatusCode(), response.getStatus());
            assertEquals("Role can't be specified multiple times - Role A", response.readEntity(OAuth2ErrorRepresentation.class).getError());
        }

        representation.getRoles().clear();
        representation.addRole("Role A");
        representation.addRole("Role B");
        representation = assertCreated(authorization, representation);

        representation.addRole("Role B");
        try {
            authorization.policies().role().findById(representation.getId()).update(representation);
            Assert.fail("should fail due to duplicated roles");
        } catch (BadRequestException bre) {
            Response response = bre.getResponse();
            assertEquals(Status.BAD_REQUEST.getStatusCode(), response.getStatus());
            assertEquals("Role can't be specified multiple times - Role B", response.readEntity(OAuth2ErrorRepresentation.class).getError());
        }
    }

    private RolePolicyRepresentation assertCreated(AuthorizationResource authorization, RolePolicyRepresentation representation) {
        RolePoliciesResource permissions = authorization.policies().role();

        try (Response response = permissions.create(representation)) {
            RolePolicyRepresentation created = response.readEntity(RolePolicyRepresentation.class);
            RolePolicyResource permission = permissions.findById(created.getId());
            assertRepresentation(representation, permission);
            return permission.toRepresentation();
        }
    }

    private void assertRepresentation(RolePolicyRepresentation representation, RolePolicyResource permission) {
        RolePolicyRepresentation actual = permission.toRepresentation();
        assertRepresentation(representation, actual, () -> permission.resources(), () -> Collections.emptyList(), () -> permission.associatedPolicies());
        assertEquals(representation.getRoles().size(), actual.getRoles().size());
        ClientRepresentation clientRep = getClient().toRepresentation();
        assertEquals(0, actual.getRoles().stream().filter(actualDefinition -> !representation.getRoles().stream()
                .filter(roleDefinition -> (getRoleName(actualDefinition.getId()).equals(roleDefinition.getId()) || (clientRep.getClientId() + "/" + getRoleName(actualDefinition.getId())).equals(roleDefinition.getId())) && actualDefinition.isRequired() == roleDefinition.isRequired())
                .findFirst().isPresent())
                .count());
        assertEquals(representation.isFetchRoles(), actual.isFetchRoles());
    }

    private String getRoleName(String id) {
        return getRealm().rolesById().getRole(id).getName();
    }
}
