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

package org.keycloak.storage.ldap.idm.query.internal;

import java.util.Arrays;
import org.keycloak.models.ModelException;
import org.keycloak.storage.ldap.idm.query.Condition;
import org.keycloak.storage.ldap.idm.query.Sort;

/**
 * @author Pedro Igor
 */
public class LDAPQueryConditionsBuilder {

    public Condition equal(String parameter, Object value) {
        return new EqualCondition(parameter, value);
    }

    public Condition greaterThan(String paramName, Object x) {
        throwExceptionIfNotComparable(x);
        return new GreaterThanCondition(paramName, (Comparable) x, false);
    }

    public Condition greaterThanOrEqualTo(String paramName, Object x) {
        throwExceptionIfNotComparable(x);
        return new GreaterThanCondition(paramName, (Comparable) x, true);
    }

    public Condition lessThan(String paramName, Comparable x) {
        return new LessThanCondition(paramName, x, false);
    }

    public Condition lessThanOrEqualTo(String paramName, Comparable x) {
        return new LessThanCondition(paramName, x, true);
    }

    public Condition between(String paramName, Comparable x, Comparable y) {
        return new BetweenCondition(paramName, x, y);
    }

    public Condition orCondition(Condition... conditions) {
        if (conditions == null || conditions.length == 0) {
            throw new ModelException("At least one condition should be provided to OR query");
        }
        return new OrCondition(conditions);
    }

    public Condition andCondition(Condition... conditions) {
        if (conditions == null || conditions.length == 0) {
            throw new ModelException("At least one condition should be provided to AND query");
        }
        return new AndCondition(conditions);
    }

    public Condition addCustomLDAPFilter(String filter) {
        filter = filter.trim();
        return new CustomLDAPFilter(filter);
    }

    public Condition in(String paramName, Object... x) {
        return new InCondition(paramName, x);
    }

    public Condition present(String paramName) {
        return new PresentCondition(paramName);
    }

    public Condition substring(String paramName, String start, String[] middle, String end) {
        if ((start == null || start.isEmpty())
                && (end == null || end.isEmpty())
                && (middle == null || middle.length == 0)) {
            throw new ModelException("Invalid substring filter with no start, middle or end");
        }
        if (middle != null && middle.length > 0 && Arrays.stream(middle).filter(s -> s == null || s.isEmpty()).findAny().isPresent()) {
            throw new ModelException("Invalid substring filter with an empty string in the middle array");
        }

        return new SubstringCondition(paramName, start, middle, end);
    }

    public Sort asc(String paramName) {
        return new Sort(paramName, true);
    }

    public Sort desc(String paramName) {
        return new Sort(paramName, false);
    }

    private void throwExceptionIfNotComparable(Object x) {
        if (!Comparable.class.isInstance(x)) {
            throw new ModelException("Query parameter value [" + x + "] must be " + Comparable.class + ".");
        }
    }
}