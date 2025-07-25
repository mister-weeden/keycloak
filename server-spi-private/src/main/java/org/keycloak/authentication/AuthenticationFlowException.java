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

package org.keycloak.authentication;

import jakarta.ws.rs.core.Response;
import java.util.List;

/**
 * Throw this exception from an Authenticator, FormAuthenticator, or FormAction if you want to completely abort the flow.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class AuthenticationFlowException extends RuntimeException {
    private AuthenticationFlowError error;
    private Response response;
    private List<AuthenticationFlowException> afeList;
    private String eventDetails;
    private String userErrorMessage;

    public AuthenticationFlowException(AuthenticationFlowError error) {
        this.error = error;
    }
    
    public AuthenticationFlowException(AuthenticationFlowError error, String eventDetails, String userErrorMessage) {
        this.error = error;
        this.eventDetails = eventDetails;
        this.userErrorMessage = userErrorMessage;
    }

    public AuthenticationFlowException(AuthenticationFlowError error, Response response) {
        this.error = error;
        this.response = response;
    }

    public AuthenticationFlowException(String message, AuthenticationFlowError error) {
        super(message);
        this.error = error;
    }

    public AuthenticationFlowException(String message, Throwable cause, AuthenticationFlowError error) {
        super(message, cause);
        this.error = error;
    }

    public AuthenticationFlowException(Throwable cause, AuthenticationFlowError error) {
        super(cause);
        this.error = error;
    }

    public AuthenticationFlowException(List<AuthenticationFlowException> afeList){
        this.error = AuthenticationFlowError.INTERNAL_ERROR;
        this.afeList = afeList;
    }

    public AuthenticationFlowException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace, AuthenticationFlowError error) {
        super(message, cause, enableSuppression, writableStackTrace);
        this.error = error;
    }

    public AuthenticationFlowError getError() {
        return error;
    }

    public Response getResponse() {
        return response;
    }

    public List<AuthenticationFlowException> getAfeList() {
        return afeList;
    }

    public String getEventDetails() {
        return eventDetails;
    }
    
    public String getUserErrorMessage() {
        return userErrorMessage;
    }
}
