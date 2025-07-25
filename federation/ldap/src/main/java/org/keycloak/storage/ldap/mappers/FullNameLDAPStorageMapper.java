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

package org.keycloak.storage.ldap.mappers;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.LDAPConstants;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.query.Condition;
import org.keycloak.storage.ldap.idm.query.internal.EqualCondition;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Mapper useful for the LDAP deployments when some attribute (usually CN) is mapped to full name of user
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class FullNameLDAPStorageMapper extends AbstractLDAPStorageMapper {

    public static final String LDAP_FULL_NAME_ATTRIBUTE = "ldap.full.name.attribute";
    public static final String READ_ONLY = "read.only";
    public static final String WRITE_ONLY = "write.only";


    public FullNameLDAPStorageMapper(ComponentModel mapperModel, LDAPStorageProvider ldapProvider) {
        super(mapperModel, ldapProvider);
    }

    @Override
    public void onImportUserFromLDAP(LDAPObject ldapUser, UserModel user, RealmModel realm, boolean isCreate) {
        if (isWriteOnly()) {
            return;
        }

        String ldapFullNameAttrName = getLdapFullNameAttrName();
        String fullName = ldapUser.getAttributeAsString(ldapFullNameAttrName);
        if (fullName == null) {
            return;
        }

        fullName = fullName.trim();
        if (!fullName.isEmpty()) {
            int lastSpaceIndex = fullName.lastIndexOf(" ");
            if (lastSpaceIndex == -1) {
                user.setLastName(fullName);
            } else {
                user.setFirstName(fullName.substring(0, lastSpaceIndex));
                user.setLastName(fullName.substring(lastSpaceIndex + 1));
            }
        }
    }

    @Override
    public void onRegisterUserToLDAP(LDAPObject ldapUser, UserModel localUser, RealmModel realm) {
        String ldapFullNameAttrName = getLdapFullNameAttrName();
        String fullName = getFullNameForWriteToLDAP(localUser.getFirstName(), localUser.getLastName(), localUser.getUsername());
        ldapUser.setSingleAttribute(ldapFullNameAttrName, fullName);

        if (isReadOnly()) {
            ldapUser.addReadOnlyAttributeName(ldapFullNameAttrName);
        }
    }

    @Override
    public UserModel proxy(LDAPObject ldapUser, UserModel delegate, RealmModel realm) {
        if (ldapProvider.getEditMode() == UserStorageProvider.EditMode.WRITABLE && !isReadOnly()) {


            TxAwareLDAPUserModelDelegate txDelegate = new TxAwareLDAPUserModelDelegate(delegate, ldapProvider, ldapUser) {

                // Per-transaction state. Useful due the fact that "setFirstName" and "setLastName" called within same transaction
                private String firstName;
                private String lastName;

                @Override
                public String getFirstName() {
                    return firstName != null ? firstName : super.getFirstName();
                }

                @Override
                public String getLastName() {
                    return lastName != null ? lastName : super.getLastName();
                }

                @Override
                public Stream<String> getAttributeStream(String name) {
                    if (UserModel.FIRST_NAME.equals(name)) {
                        return firstName != null ? Stream.of(firstName) : super.getAttributeStream(name);
                    } else if (UserModel.LAST_NAME.equals(name)) {
                        return lastName != null ? Stream.of(lastName) : super.getAttributeStream(name);
                    }
                    return super.getAttributeStream(name);
                }

                @Override
                public String getFirstAttribute(String name) {
                    if (UserModel.FIRST_NAME.equals(name)) {
                        return firstName != null ? firstName : super.getFirstAttribute(name);
                    } else if (UserModel.LAST_NAME.equals(name)) {
                        return lastName != null ? lastName : super.getFirstAttribute(name);
                    }
                    return super.getFirstAttribute(name);
                }

                @Override
                public void setSingleAttribute(String name, String value) {
                    if (UserModel.FIRST_NAME.equals(name)) {
                        this.firstName = value;
                        setFullNameToLDAPObject();
                    } else if (UserModel.LAST_NAME.equals(name)) {
                        this.lastName = value;
                        setFullNameToLDAPObject();
                    }
                    super.setSingleAttribute(name, value);
                }

                @Override
                public void setAttribute(String name, List<String> values) {
                    String valueToSet = (values != null && !values.isEmpty()) ? values.get(0) : null;
                    if (UserModel.FIRST_NAME.equals(name)) {
                        this.firstName = valueToSet;
                        setFullNameToLDAPObject();
                    } else if (UserModel.LAST_NAME.equals(name)) {
                        this.lastName = valueToSet;
                        setFullNameToLDAPObject();
                    }
                    super.setAttribute(name, values);
                }

                @Override
                public Map<String, List<String>> getAttributes() {
                    Map<String, List<String>> attributes = delegate.getAttributes();
                    if (firstName != null) {
                        attributes.put(UserModel.FIRST_NAME, Collections.singletonList(firstName));
                    } else if (lastName != null) {
                        attributes.put(UserModel.FIRST_NAME, Collections.singletonList(lastName));
                    }
                    return attributes;
                }


                private void setFullNameToLDAPObject() {
                    String fullName = getFullNameForWriteToLDAP(getFirstName(), getLastName(), getUsername());
                    if (logger.isTraceEnabled()) {
                        logger.tracef("Pushing full name attribute to LDAP. Full name: %s", fullName);
                    }

                    markUpdatedAttributeInTransaction(UserModel.FIRST_NAME);
                    markUpdatedAttributeInTransaction(UserModel.LAST_NAME);

                    String ldapFullNameAttrName = getLdapFullNameAttrName();
                    ldapUser.setSingleAttribute(ldapFullNameAttrName, fullName);
                }
            };

            return txDelegate;
        } else {
            return delegate;
        }
    }

    @Override
    public void beforeLDAPQuery(LDAPQuery query) {
        if (isWriteOnly()) {
            return;
        }

        String ldapFullNameAttrName = getLdapFullNameAttrName();
        query.addReturningLdapAttribute(ldapFullNameAttrName);

        // Change conditions and compute condition for fullName from the conditions for firstName and lastName. Right now just "equal" condition is supported
        EqualCondition firstNameCondition = null;
        EqualCondition lastNameCondition = null;
        Set<Condition> conditionsCopy = new HashSet<Condition>(query.getConditions());
        for (Condition condition : conditionsCopy) {
            String paramName = condition.getParameterName();
            if (paramName != null) {
                if (paramName.equals(UserModel.FIRST_NAME)) {
                    firstNameCondition = (EqualCondition) condition;
                    query.getConditions().remove(condition);
                } else if (paramName.equals(UserModel.LAST_NAME)) {
                    lastNameCondition = (EqualCondition) condition;
                    query.getConditions().remove(condition);
                } else if (paramName.equals(LDAPConstants.GIVENNAME)) {
                    // Some previous mapper already converted it to LDAP name
                    firstNameCondition = (EqualCondition) condition;
                } else if (paramName.equals(LDAPConstants.SN)) {
                    // Some previous mapper already converted it to LDAP name
                    lastNameCondition = (EqualCondition) condition;
                }
            }
        }


        String fullName = null;
        if (firstNameCondition != null && lastNameCondition != null) {
            fullName = firstNameCondition.getValue() + " " + lastNameCondition.getValue();
        } else if (firstNameCondition != null) {
            fullName = (String) firstNameCondition.getValue();
        } else if (lastNameCondition != null) {
            fullName = (String) lastNameCondition.getValue();
        } else {
            return;
        }

        EqualCondition fullNameCondition = new EqualCondition(ldapFullNameAttrName, fullName);
        query.addWhereCondition(fullNameCondition);
    }

    @Override
    public Set<String> getUserAttributes() {
        return new HashSet<>(List.of(UserModel.FIRST_NAME, UserModel.LAST_NAME));
    }

    protected String getLdapFullNameAttrName() {
        String ldapFullNameAttrName = mapperModel.getConfig().getFirst(LDAP_FULL_NAME_ATTRIBUTE);
        return ldapFullNameAttrName == null ? LDAPConstants.CN : ldapFullNameAttrName;
    }

    protected String getFullNameForWriteToLDAP(String firstName, String lastName, String username) {
        if (!isBlank(firstName) && !isBlank(lastName)) {
            return firstName + " " + lastName;
        } else if (!isBlank(firstName)) {
            return firstName;
        } else if (!isBlank(lastName)) {
            return lastName;
        } else if (isFallbackToUsername()) {
            return username;
        } else {
            return LDAPConstants.EMPTY_ATTRIBUTE_VALUE;
        }
    }

    private boolean isBlank(String attr) {
        return attr == null || attr.trim().isEmpty();
    }

    private boolean isReadOnly() {
        return parseBooleanParameter(mapperModel, READ_ONLY);
    }

    private boolean isWriteOnly() {
        return parseBooleanParameter(mapperModel, WRITE_ONLY);
    }


    // Used just in case that we have Writable LDAP and fullName is mapped to "cn", which is used as RDN (this typically happens only on MSAD)
    private boolean isFallbackToUsername() {
        String rdnLdapAttrConfig = getLdapProvider().getLdapIdentityStore().getConfig().getRdnLdapAttribute();
        return !isReadOnly() && getLdapFullNameAttrName().equalsIgnoreCase(rdnLdapAttrConfig);
    }
}
