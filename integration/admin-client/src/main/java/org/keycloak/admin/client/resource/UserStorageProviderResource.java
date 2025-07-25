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

import org.keycloak.representations.idm.SynchronizationResultRepresentation;

import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public interface UserStorageProviderResource {
    /**
     * If the provider supports synchronization, this will invoke it.
     *
     * Action can be "triggerFullSync" or "triggerChangedUsersSync"
     *
     *
     * @param componentId
     * @param action
     * @return
     */
    @POST
    @Path("{componentId}/sync")
    @Produces(MediaType.APPLICATION_JSON)
    SynchronizationResultRepresentation syncUsers(@PathParam("componentId") String componentId, @QueryParam("action") String action);

    /**
     * Remove imported users
     *
     *
     * @param componentId
     * @return
     */
    @POST
    @Path("{componentId}/remove-imported-users")
    @Produces(MediaType.APPLICATION_JSON)
    void removeImportedUsers(@PathParam("componentId") String componentId);

    /**
     * Unlink imported users from a storage provider
     *
     * @param componentId
     * @return
     */
    @POST
    @Path("{componentId}/unlink-users")
    @Produces(MediaType.APPLICATION_JSON)
    void unlink(@PathParam("componentId") String componentId);

    /**
     * REST invocation for initiating sync for an ldap mapper.  This method may be moved in the future.  Right now
     * don't have a good place for it.
     *
     * direction is "fedToKeycloak" or "keycloakToFed"
     *
     *
     * @param componentId
     * @param mapperId
     * @param direction
     * @return
     */
    @POST
    @Path("{componentId}/mappers/{mapperId}/sync")
    @Produces(MediaType.APPLICATION_JSON)
    SynchronizationResultRepresentation syncMapperData(@PathParam("componentId") String componentId, @PathParam("mapperId") String mapperId, @QueryParam("direction") String direction);


}
