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


import java.util.List;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class ProfileInfoRepresentation {

    private String name;
    private List<String> disabledFeatures;
    private List<String> previewFeatures;
    private List<String> experimentalFeatures;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<String> getDisabledFeatures() {
        return disabledFeatures;
    }

    public void setDisabledFeatures(List<String> disabledFeatures) {
        this.disabledFeatures = disabledFeatures;
    }

    public List<String> getPreviewFeatures() {
        return previewFeatures;
    }

    public void setPreviewFeatures(List<String> previewFeatures) {
        this.previewFeatures = previewFeatures;
    }

    public List<String> getExperimentalFeatures() {
        return experimentalFeatures;
    }

    public void setExperimentalFeatures(List<String> experimentalFeatures) {
        this.experimentalFeatures = experimentalFeatures;
    }

}
