/*
 * Copyright 2024 Scott Weeden and/or his affiliates
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

package org.keycloak.forms.login.freemarker.model;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.keycloak.models.OrganizationDomainModel;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.UserModel;

public class OrganizationBean {

    private final String name;
    private final String alias;
    private final Set<String> domains;
    private final boolean isMember;
    private final Map<String, List<String>> attributes;

    public OrganizationBean(OrganizationModel organization, UserModel user) {
        this.name = organization.getName();
        this.alias = organization.getAlias();
        this.domains = organization.getDomains().map(OrganizationDomainModel::getName).collect(Collectors.toSet());
        this.isMember = user != null && organization.isMember(user);
        this.attributes = Collections.unmodifiableMap(organization.getAttributes());
    }

    public String getName() {
        return name;
    }

    public String getAlias() {
        return alias;
    }

    public Set<String> getDomains() {
        return domains;
    }

    public Map<String, List<String>> getAttributes() {
        return attributes;
    }

    public boolean isMember() {
        return isMember;
    }
}
