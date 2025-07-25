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
package org.keycloak.dom.saml.common;

import org.w3c.dom.Element;

import javax.xml.datatype.XMLGregorianCalendar;
import java.io.Serializable;

/**
 * SAML Request Abstract Type
 *
 * @author Anil.Saldhana@redhat.com
 * @since Jun 22, 2011
 */
public abstract class CommonRequestAbstractType implements Serializable {

    protected String id;

    protected XMLGregorianCalendar issueInstant;

    protected Element signature;

    public CommonRequestAbstractType(String id, XMLGregorianCalendar issueInstant) {
        this.id = id;
        this.issueInstant = issueInstant;
    }

    /**
     * Gets the value of the id property.
     *
     * @return possible object is {@link String }
     */
    public String getID() {
        return id;
    }

    /**
     * Gets the value of the issueInstant property.
     *
     * @return possible object is {@link XMLGregorianCalendar }
     */
    public XMLGregorianCalendar getIssueInstant() {
        return issueInstant;
    }

    /**
     * Gets the value of the signature property.
     *
     * @return possible object is {@link org.keycloak.dom.xmlsec.w3.xmldsig.SignatureType }
     */
    public Element getSignature() {
        return signature;
    }

    /**
     * Sets the value of the signature property.
     *
     * @param value allowed object is {@link org.keycloak.dom.xmlsec.w3.xmldsig.SignatureType }
     */
    public void setSignature(Element value) {
        this.signature = value;
    }
}