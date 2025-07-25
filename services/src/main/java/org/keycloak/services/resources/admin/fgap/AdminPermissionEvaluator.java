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
package org.keycloak.services.resources.admin.fgap;

import org.keycloak.services.resources.admin.AdminAuth;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public interface AdminPermissionEvaluator {
    RealmPermissionEvaluator realm();

    void requireAnyAdminRole();
    boolean hasOneAdminRole(String... adminRoles);

    AdminAuth adminAuth();

    RolePermissionEvaluator roles();
    UserPermissionEvaluator users();
    ClientPermissionEvaluator clients();
    GroupPermissionEvaluator groups();

    /**
     * Useful as a function pointer, i.e. RoleMapperResource is reused bewteen GroupResource and UserResource to manage role mappings.
     * We don't know what type of resource we're managing here (user or group), so we don't know how to query the policy engine to determine
     * if an action is allowed.
     *
     */
    interface PermissionCheck {
        boolean evaluate();
    }
    /**
     * Useful as a function pointer, i.e. RoleMapperResource is reused bewteen GroupResource and UserResource to manage role mappings.
     * We don't know what type of resource we're managing here (user or group), so we don't know how to query the policy engine to determine
     * if an action is allowed.
     *
     * throws appropriate exception if permission is deny
     *
     */
    interface RequirePermissionCheck {
        void require();
    }
}
