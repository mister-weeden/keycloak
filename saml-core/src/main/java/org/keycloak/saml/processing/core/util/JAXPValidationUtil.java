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
package org.keycloak.saml.processing.core.util;

import org.keycloak.saml.common.PicketLinkLogger;
import org.keycloak.saml.common.PicketLinkLoggerFactory;
import org.keycloak.saml.common.constants.GeneralConstants;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.common.util.SecurityActions;
import org.keycloak.saml.common.util.StaxParserUtil;
import org.keycloak.saml.common.util.SystemPropertiesUtil;
import org.w3c.dom.Node;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.transform.stax.StAXSource;
import org.xml.sax.SAXNotRecognizedException;
import org.xml.sax.SAXNotSupportedException;
import static org.keycloak.saml.common.util.DocumentUtil.feature_disallow_doctype_decl;
import static org.keycloak.saml.common.util.DocumentUtil.feature_external_general_entities;
import static org.keycloak.saml.common.util.DocumentUtil.feature_external_parameter_entities;

/**
 * Utility class associated with JAXP Validation
 *
 * @author Anil.Saldhana@redhat.com
 * @since Jun 30, 2011
 */
public class JAXPValidationUtil {

    private static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();

    protected static Validator validator;

    protected static SchemaFactory schemaFactory;

    public static void validate(InputStream stream) throws SAXException, IOException {
        try {
            validator().validate(new StAXSource(StaxParserUtil.getXMLEventReader(stream)));
        } catch (XMLStreamException ex) {
            throw new IOException(ex);
        }
    }

    /**
     * Based on system property "picketlink.schema.validate" set to "true", do schema validation
     *
     * @param samlDocument
     *
     * @throws org.keycloak.saml.common.exceptions.ProcessingException
     */
    public static void checkSchemaValidation(Node samlDocument) throws ProcessingException {
        if (SecurityActions.getSystemProperty("picketlink.schema.validate", "false").equalsIgnoreCase("true")) {
            try {
                JAXPValidationUtil.validate(DocumentUtil.getNodeAsStream(samlDocument));
            } catch (Exception e) {
                throw logger.processingError(e);
            }
        }
    }

    public static Validator validator() throws SAXException, IOException {
        SystemPropertiesUtil.ensure();

        if (validator == null) {
            Schema schema = getSchema();
            if (schema == null)
                throw logger.nullValueError("schema");

            validator = schema.newValidator();
            // Do not optimize the following into setProperty(...) && setProperty(...).
            // This way if it fails in the first setProperty, it will try the subsequent setProperty anyway
            // which it would not due to short-circuiting in case of an && expression.
            boolean successful1 = setProperty(validator, FixXMLConstants.ACCESS_EXTERNAL_DTD, "");
            successful1 &= setProperty(validator, FixXMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            boolean successful2 = setFeature(validator, feature_disallow_doctype_decl, true);
            successful2 &= setFeature(validator, feature_external_general_entities, false);
            successful2 &= setFeature(validator, feature_external_parameter_entities, false);
            if (! successful1 && ! successful2) {
                logger.warn("Cannot disable external access in XML validator");
            }
            validator.setErrorHandler(new CustomErrorHandler());
        }
        return validator;
    }

    private static boolean setProperty(Validator v, String property, String value) {
        try {
            v.setProperty(property, value);
        } catch (SAXNotRecognizedException | SAXNotSupportedException ex) {
            logger.debug("Cannot set " + property);
            return false;
        }
        return true;
    }

    private static boolean setFeature(Validator v, String feature, boolean value) {
        try {
            v.setFeature(feature, value);
        } catch (SAXNotRecognizedException | SAXNotSupportedException ex) {
            logger.debug("Cannot set " + feature);
            return false;
        }
        return true;
    }

    private static Schema getSchema() throws IOException {
        boolean tccl_jaxp = SystemPropertiesUtil.getSystemProperty(GeneralConstants.TCCL_JAXP, "false").equalsIgnoreCase("true");

        ClassLoader prevTCCL = SecurityActions.getTCCL();
        try {
            if (tccl_jaxp) {
                SecurityActions.setTCCL(JAXPValidationUtil.class.getClassLoader());
            }
            schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);

            schemaFactory.setResourceResolver(new IDFedLSInputResolver());
            schemaFactory.setErrorHandler(new CustomErrorHandler());
        } finally {
            if (tccl_jaxp) {
                SecurityActions.setTCCL(prevTCCL);
            }
        }
        Schema schemaGrammar = null;
        try {
            schemaGrammar = schemaFactory.newSchema(sources());
        } catch (SAXException e) {
            logger.xmlCouldNotGetSchema(e);
        }
        return schemaGrammar;
    }

    private static Source[] sources() throws IOException {
        List<String> schemas = SchemaManagerUtil.getSchemas();

        Source[] sourceArr = new Source[schemas.size()];

        int i = 0;
        for (String schema : schemas) {
            URL url = SecurityActions.loadResource(JAXPValidationUtil.class, schema);
            if (url == null)
                throw logger.nullValueError("schema url:" + schema);
            sourceArr[i++] = new StreamSource(url.openStream());
        }
        return sourceArr;
    }

    private static class CustomErrorHandler implements ErrorHandler {

        public void error(SAXParseException ex) throws SAXException {
            logException(ex);
            if (!ex.getMessage().contains("null")) {
                throw ex;
            }
        }

        public void fatalError(SAXParseException ex) throws SAXException {
            logException(ex);
            throw ex;
        }

        public void warning(SAXParseException ex) throws SAXException {
            logException(ex);
        }

        private void logException(SAXParseException sax) {
            StringBuilder builder = new StringBuilder();

            if (logger.isTraceEnabled()) {
                builder.append("[line:").append(sax.getLineNumber()).append(",").append("::col=").append(sax.getColumnNumber())
                        .append("]");
                builder.append("[publicID:").append(sax.getPublicId()).append(",systemId=").append(sax.getSystemId())
                        .append("]");
                builder.append(":").append(sax.getLocalizedMessage());
                logger.trace(builder.toString());
            }
        }
    }

    ;
}