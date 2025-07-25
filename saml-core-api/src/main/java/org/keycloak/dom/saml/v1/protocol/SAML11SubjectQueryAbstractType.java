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
package org.keycloak.dom.saml.v1.protocol;

import org.keycloak.dom.saml.v1.assertion.SAML11SubjectType;

/**
 * <complexType name="SubjectQueryAbstractType" abstract="true"> <complexContent> <extension
 * base="samlp:QueryAbstractType">
 * <sequence> <element ref="saml:Subject"/> </sequence>
 *
 * </extension> </complexContent> </complexType>
 *
 * @author Anil.Saldhana@redhat.com
 * @since Jun 22, 2011
 */
public class SAML11SubjectQueryAbstractType extends SAML11QueryAbstractType {

    protected SAML11SubjectType subject;

    public SAML11SubjectType getSubject() {
        return subject;
    }

    public void setSubject(SAML11SubjectType subject) {
        this.subject = subject;
    }
}