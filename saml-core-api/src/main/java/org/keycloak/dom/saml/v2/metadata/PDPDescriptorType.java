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
package org.keycloak.dom.saml.v2.metadata;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * <p>
 * Java class for PDPDescriptorType complex type.
 *
 * <p>
 * The following schema fragment specifies the expected content contained within this class.
 *
 * <pre>
 * &lt;complexType name="PDPDescriptorType">
 *   &lt;complexContent>
 *     &lt;extension base="{urn:oasis:names:tc:SAML:2.0:metadata}RoleDescriptorType">
 *       &lt;sequence>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}AuthzService" maxOccurs="unbounded"/>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}AssertionIDRequestService" maxOccurs="unbounded"
 * minOccurs="0"/>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:metadata}NameIDFormat" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 */
public class PDPDescriptorType extends RoleDescriptorType {

    protected List<EndpointType> authzService = new ArrayList<>();

    protected List<EndpointType> assertionIDRequestService = new ArrayList<>();

    protected List<String> nameIDFormat = new ArrayList<>();

    public PDPDescriptorType(List<String> protocolSupport) {
        super(protocolSupport);
    }

    /**
     * Add authorization service
     *
     * @param endpt
     */
    public void addAuthZService(EndpointType endpt) {
        this.authzService.add(endpt);
    }

    /**
     * Add assertion id request service
     *
     * @param endpt
     */
    public void addAssertionIDRequestService(EndpointType endpt) {
        this.assertionIDRequestService.add(endpt);
    }

    /**
     * Add Name ID Format
     *
     * @param str
     */
    public void addNameIDFormat(String str) {
        this.nameIDFormat.add(str);
    }

    /**
     * remove authorization service
     *
     * @param endpt
     */
    public void removeAuthZService(EndpointType endpt) {
        this.authzService.remove(endpt);
    }

    /**
     * remove assertion id request service
     *
     * @param endpt
     */
    public void removeAssertionIDRequestService(EndpointType endpt) {
        this.assertionIDRequestService.remove(endpt);
    }

    /**
     * remove Name ID Format
     *
     * @param str
     */
    public void removeNameIDFormat(String str) {
        this.nameIDFormat.remove(str);
    }

    /**
     * Gets the value of the authzService property.
     * <p>
     * Objects of the following type(s) are allowed in the list {@link EndpointType }
     */
    public List<EndpointType> getAuthzService() {
        return Collections.unmodifiableList(this.authzService);
    }

    /**
     * Gets the value of the assertionIDRequestService property.
     *
     * <p>
     * Objects of the following type(s) are allowed in the list {@link EndpointType }
     */
    public List<EndpointType> getAssertionIDRequestService() {
        return Collections.unmodifiableList(this.assertionIDRequestService);
    }

    /**
     * Gets the value of the nameIDFormat property.
     * <p>
     * Objects of the following type(s) are allowed in the list {@link String }
     */
    public List<String> getNameIDFormat() {
        return Collections.unmodifiableList(this.nameIDFormat);
    }
}