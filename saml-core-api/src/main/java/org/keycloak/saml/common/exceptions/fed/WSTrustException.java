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
 * <p>
 * Exception used to convey that an error has happened when handling a WS-Trust request message.
 * </p>
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class WSTrustException extends GeneralSecurityException {

    /**
     * <p>
     * Creates an instance of {@code WSTrustException} using the specified error message.
     * </p>
     *
     * @param message the error message.
     */
    public WSTrustException(String message) {
        super(message);
    }

    /**
     * <p>
     * Creates an instance of {@code WSTrustException} using the specified error message and cause.
     * </p>
     *
     * @param message the error message.
     * @param cause a {@code Throwable} representing the cause of the error.
     */
    public WSTrustException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * <p>
     * Creates an instance of {@code WSTrustException} using the specified {@link Throwable}.
     * </p>
     *
     * @param message the error message.
     */
    public WSTrustException(Throwable t) {
        super(t);
    }

}