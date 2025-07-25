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

package org.keycloak.client.registration;

import com.fasterxml.jackson.annotation.JsonIgnore;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
abstract class OIDCClientRepresentationMixIn {

    @JsonIgnore
    private Integer client_id_issued_at;

    @JsonIgnore
    private Integer client_secret_expires_at;

    @JsonIgnore
    private String registration_client_uri;

    @JsonIgnore
    private String registration_access_token;

}
