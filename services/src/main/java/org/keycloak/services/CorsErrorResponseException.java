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

package org.keycloak.services;

import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.services.cors.Cors;

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class CorsErrorResponseException extends WebApplicationException {

    private final Cors cors;
    private final String error;
    private final String errorDescription;
    private final Response.Status status;

    public CorsErrorResponseException(Cors cors, String error, String errorDescription, Response.Status status) {
        super(error, status);
        this.cors = cors;
        this.error = error;
        this.errorDescription = errorDescription;
        this.status = status;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    @Override
    public Response getResponse() {
        OAuth2ErrorRepresentation errorRep = new OAuth2ErrorRepresentation(error, errorDescription);
        Response.ResponseBuilder builder = Response.status(status).entity(errorRep).type(MediaType.APPLICATION_JSON_TYPE);
        return cors.add(builder);
    }

}
