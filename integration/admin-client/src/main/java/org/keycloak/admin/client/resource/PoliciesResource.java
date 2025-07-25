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

import org.keycloak.representations.idm.authorization.PolicyEvaluationRequest;
import org.keycloak.representations.idm.authorization.PolicyEvaluationResponse;
import org.keycloak.representations.idm.authorization.PolicyProviderRepresentation;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface PoliciesResource {

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    Response create(PolicyRepresentation representation);

    @Path("{id}")
    PolicyResource policy(@PathParam("id") String id);

    @Path("/search")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    PolicyRepresentation findByName(@QueryParam("name") String name);

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    List<PolicyRepresentation> policies();

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    List<PolicyRepresentation> policies(@QueryParam("policyId") String id,
            @QueryParam("name") String name,
            @QueryParam("type") String type,
            @QueryParam("resource") String resource,
            @QueryParam("scope") String scope,
            @QueryParam("permission") Boolean permission,
            @QueryParam("owner") String owner,
            @QueryParam("fields") String fields,
            @QueryParam("first") Integer firstResult,
            @QueryParam("max") Integer maxResult);

    @Path("providers")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    List<PolicyProviderRepresentation> policyProviders();

    @POST
    @Consumes("application/json")
    @Produces("application/json")
    @Path("evaluate")
    PolicyEvaluationResponse evaluate(PolicyEvaluationRequest evaluationRequest);

    @Path("role")
    RolePoliciesResource role();

    @Path("user")
    UserPoliciesResource user();

    @Path("js")
    JSPoliciesResource js();

    @Path("time")
    TimePoliciesResource time();

    @Path("aggregate")
    AggregatePoliciesResource aggregate();

    @Path("client")
    ClientPoliciesResource client();

    @Path("group")
    GroupPoliciesResource group();

    @Path("client-scope")
    ClientScopePoliciesResource clientScope();
    
    @Path("regex")
    RegexPoliciesResource regex();
}
