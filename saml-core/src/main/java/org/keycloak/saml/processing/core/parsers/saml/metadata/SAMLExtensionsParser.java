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
package org.keycloak.saml.processing.core.parsers.saml.metadata;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.StartElement;

import org.keycloak.dom.saml.v2.metadata.ExtensionsType;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.util.StaxParserUtil;
import org.keycloak.saml.processing.core.parsers.saml.mdattr.SAMLEntityAttributesParser;
import org.keycloak.saml.processing.core.parsers.saml.mdui.SAMLUIInfoParser;

/**
 * Parses &lt;samlp:Extensions&gt; SAML2 element into series of DOM nodes.
 *
 * @author hmlnarik
 */
public class SAMLExtensionsParser extends AbstractStaxSamlMetadataParser<ExtensionsType> {

    private static final SAMLExtensionsParser INSTANCE = new SAMLExtensionsParser();

    private SAMLExtensionsParser() {
        super(SAMLMetadataQNames.EXTENSIONS);
    }

    public static SAMLExtensionsParser getInstance() {
        return INSTANCE;
    }

    @Override
    protected ExtensionsType instantiateElement(XMLEventReader xmlEventReader, StartElement element) throws ParsingException {
        return new ExtensionsType();
    }

    @Override
    protected void processSubElement(XMLEventReader xmlEventReader, ExtensionsType target, SAMLMetadataQNames element,
        StartElement elementDetail) throws ParsingException {

        switch (element) {
            case UIINFO:
                target.addExtension(SAMLUIInfoParser.getInstance().parse(xmlEventReader));
                break;
            case ENTITY_ATTRIBUTES:
                target.addExtension(SAMLEntityAttributesParser.getInstance().parse(xmlEventReader));
                break;
            default:
                target.addExtension(StaxParserUtil.getDOMElement(xmlEventReader));
        }

    }
}
