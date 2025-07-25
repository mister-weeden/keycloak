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
package org.keycloak.saml.common.exceptions.fed;

import java.security.GeneralSecurityException;

/**
 * Security Exception indicating expiration of SAML2 assertion
 *
 * @author Anil.Saldhana@redhat.com
 * @since Dec 12, 2008
 */
public class AssertionExpiredException extends GeneralSecurityException {

    protected String id;

    public AssertionExpiredException() {
    }

    public AssertionExpiredException(String message, Throwable cause) {
    }

    public AssertionExpiredException(String msg) {
        super(msg);
    }

    public AssertionExpiredException(Throwable cause) {
        super(cause);
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }
}