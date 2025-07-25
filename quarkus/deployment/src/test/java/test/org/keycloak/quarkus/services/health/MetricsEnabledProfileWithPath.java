/*
 * Copyright 2025 Scott Weeden and/or his affiliates
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

package test.org.keycloak.quarkus.services.health;

import java.util.HashMap;
import java.util.Map;

public class MetricsEnabledProfileWithPath extends MetricsEnabledProfile {

    @Override
    public Map<String, String> getConfigOverrides() {
        HashMap<String, String> config = new HashMap<>();
        config.put("kc.http-relative-path","/auth");
        config.putAll(super.getConfigOverrides());
        return config;
    }

}