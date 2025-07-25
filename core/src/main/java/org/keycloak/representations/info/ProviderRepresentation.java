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

package org.keycloak.representations.info;

import java.util.Map;

public class ProviderRepresentation {

    private int order;

    private Map<String, String> operationalInfo;

    public int getOrder() {
        return order;
    }

    public void setOrder(int priorityUI) {
        this.order = priorityUI;
    }

    public Map<String, String> getOperationalInfo() {
        return operationalInfo;
    }

    public void setOperationalInfo(Map<String, String> operationalInfo) {
        this.operationalInfo = operationalInfo;
    }

}
