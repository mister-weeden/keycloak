/*
 *  Copyright 2016 Scott Weeden and/or his affiliates
 *  and other contributors as indicated by the @author tags.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.keycloak.authorization.client.util;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class HttpResponseException extends RuntimeException {

    private final int statusCode;
    private final String reasonPhrase;
    private final byte[] bytes;

    public HttpResponseException(String message, int statusCode, String reasonPhrase, byte[] bytes) {
        super(message);
        this.statusCode = statusCode;
        this.reasonPhrase = reasonPhrase;
        this.bytes = bytes;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getReasonPhrase() {
        return reasonPhrase;
    }

    public byte[] getBytes() {
        return bytes;
    }

    @Override
    public String toString() {
        if (bytes != null) {
            return new StringBuilder(super.toString()).append(" / Response from server: ").append(new String(bytes)).toString();
        }
        return super.toString();
    }
}
