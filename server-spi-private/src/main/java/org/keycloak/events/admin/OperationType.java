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

package org.keycloak.events.admin;

import java.util.Map;
import java.util.Objects;
import org.keycloak.util.EnumWithStableIndex;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public enum OperationType implements EnumWithStableIndex {

    CREATE(0),
    UPDATE(1),
    DELETE(2),
    ACTION(3);

    private final int stableIndex;
    private static final Map<Integer, OperationType> BY_ID = EnumWithStableIndex.getReverseIndex(values());

    private OperationType(int stableIndex) {
        Objects.requireNonNull(stableIndex);
        this.stableIndex = stableIndex;
    }

    @Override
    public int getStableIndex() {
        return stableIndex;
    }

    public static OperationType valueOfInteger(Integer id) {
        return id == null ? null : BY_ID.get(id);
    }
}
