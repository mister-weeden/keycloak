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

package org.keycloak.admin.client.resource;

import java.util.List;
import java.util.Map;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;

import jakarta.ws.rs.core.Response;
import org.keycloak.representations.adapters.action.GlobalRequestResult;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.ManagementPermissionReference;
import org.keycloak.representations.idm.ManagementPermissionRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.UserSessionRepresentation;

/**
 * @author rodrigo.sasaki@icarros.com.br
 */
public interface ClientResource {

    /**
     * Enables or disables the fine grain permissions feature.
     * Returns the updated status of the server in the
     * {@link ManagementPermissionReference}.
     *
     * @param status status request to apply
     * @return permission reference indicating the updated status
     */
    @PUT
    @Path("/management/permissions")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    ManagementPermissionReference setPermissions(ManagementPermissionRepresentation status);

    /**
     * Returns indicator if the fine grain permissions are enabled or not.
     *
     * @return current representation of the permissions feature
     */
    @GET
    @Path("/management/permissions")
    @Produces(MediaType.APPLICATION_JSON)
    ManagementPermissionReference getPermissions();

    @Path("protocol-mappers")
    ProtocolMappersResource getProtocolMappers();

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    ClientRepresentation toRepresentation();

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    void update(ClientRepresentation clientRepresentation);

    @DELETE
    void remove();

    @POST
    @Path("client-secret")
    @Produces(MediaType.APPLICATION_JSON)
    CredentialRepresentation generateNewSecret();

    @GET
    @Path("client-secret")
    @Produces(MediaType.APPLICATION_JSON)
    CredentialRepresentation getSecret();

    /**
     * Generate a new registration access token for the client
     *
     * @return
     */
    @Path("registration-access-token")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    ClientRepresentation regenerateRegistrationAccessToken();

    /**
     * Get representation of certificate resource
     *
     * @param attributePrefix
     * @return
     */
    @Path("certificates/{attr}")
    ClientAttributeCertificateResource getCertficateResource(@PathParam("attr") String attributePrefix);

    /**
     * Return installation provider as a String. String is typically XML format specific to the requested provider
     *
     * @param providerId installation provider ID
     * @return response as a string
     */
    @GET
    @Path("installation/providers/{providerId}")
    String getInstallationProvider(@PathParam("providerId") String providerId);

    /**
     * Return installation provider as a response
     *
     * @param providerId installation provider ID
     * @return Jakarta response
     */
    @GET
    @Path("installation/providers/{providerId}")
    Response getInstallationProviderAsResponse(@PathParam("providerId") String providerId);

    @Path("session-count")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    Map<String, Integer> getApplicationSessionCount();

    @Path("user-sessions")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    List<UserSessionRepresentation> getUserSessions(@QueryParam("first") Integer firstResult, @QueryParam("max") Integer maxResults);

    @Path("offline-session-count")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    Map<String, Long> getOfflineSessionCount();

    @Path("offline-sessions")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    List<UserSessionRepresentation> getOfflineUserSessions(@QueryParam("first") Integer firstResult, @QueryParam("max") Integer maxResults);

    @POST
    @Path("push-revocation")
    @Produces(MediaType.APPLICATION_JSON)
    void pushRevocation();

    @Path("/scope-mappings")
    RoleMappingResource getScopeMappings();

    @Path("/roles")
    RolesResource roles();

    @Path("/evaluate-scopes")
    ClientScopeEvaluateResource clientScopesEvaluate();

    /**
     * Get default client scopes.  Only name and ids are returned.
     *
     * @return default client scopes
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("default-client-scopes")
    List<ClientScopeRepresentation> getDefaultClientScopes();

    @PUT
    @Path("default-client-scopes/{clientScopeId}")
    void addDefaultClientScope(@PathParam("clientScopeId") String clientScopeId);

    @DELETE
    @Path("default-client-scopes/{clientScopeId}")
    void removeDefaultClientScope(@PathParam("clientScopeId") String clientScopeId);

    /**
     * Get optional client scopes.  Only name and ids are returned.
     *
     * @return optional client scopes
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("optional-client-scopes")
    List<ClientScopeRepresentation> getOptionalClientScopes();

    @PUT
    @Path("optional-client-scopes/{clientScopeId}")
    void addOptionalClientScope(@PathParam("clientScopeId") String clientScopeId);

    @DELETE
    @Path("optional-client-scopes/{clientScopeId}")
    void removeOptionalClientScope(@PathParam("clientScopeId") String clientScopeId);

    @Path("/service-account-user")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    UserRepresentation getServiceAccountUser();

    @Path("nodes")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    void registerNode(Map<String, String> formParams);

    @Path("nodes/{node}")
    @DELETE
    void unregisterNode(final @PathParam("node") String node);

    @Path("test-nodes-available")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    GlobalRequestResult testNodesAvailable();

    @Path("/authz/resource-server")
    AuthorizationResource authorization();


    @Path("client-secret/rotated")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public CredentialRepresentation getClientRotatedSecret();

    @Path("client-secret/rotated")
    @DELETE
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public void invalidateRotatedSecret();
}
