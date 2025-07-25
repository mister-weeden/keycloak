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
package org.keycloak.representations.idm.authorization;

import java.util.HashSet;
import java.util.Set;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class UserPolicyRepresentation extends AbstractPolicyRepresentation {

    private Set<String> users;

    @Override
    public String getType() {
        return "user";
    }

    public Set<String> getUsers() {
        return users;
    }

    public void setUsers(Set<String> users) {
        this.users= users;
    }

    public void addUser(String name) {
        if (users == null) {
            users = new HashSet<>();
        }
        users.add(name);
    }
}
