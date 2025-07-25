/*
 * Copyright 2022 Scott Weeden and/or his affiliates
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

package org.keycloak.operator;

import io.fabric8.kubernetes.api.model.Quantity;
import io.smallrye.config.ConfigMapping;

import java.util.Map;

/**
 * @author Vaclav Muzikar <vmuzikar@redhat.com>
 */
@ConfigMapping(prefix = "kc.operator")
public interface Config {
    Keycloak keycloak();

    interface Keycloak {
        String image();
        String imagePullPolicy();
        boolean startOptimized();
        int pollIntervalSeconds();
        long updatePodDeadlineSeconds();

        ResourceRequirements resources();
        Map<String, String> podLabels();
    }

    interface ResourceRequirements {
        Resources requests();
        Resources limits();

        interface Resources {
            Quantity memory();
        }
    }
}
