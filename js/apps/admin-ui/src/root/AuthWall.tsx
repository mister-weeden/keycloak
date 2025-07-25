import { AccessType } from "@mister-weeden/keycloak-admin-client/lib/defs/whoAmIRepresentation";
import { useMatches } from "react-router-dom";

import { ForbiddenSection } from "../ForbiddenSection";
import { useAccess } from "../context/access/Access";
import { useWhoAmI } from "../context/whoami/WhoAmI";
import { KeycloakSpinner } from "@mister-weeden/keycloak-ui-shared";

function hasProp<K extends PropertyKey>(
  data: object,
  prop: K,
): data is Record<K, unknown> {
  return prop in data;
}

export const AuthWall = ({ children }: any) => {
  const matches = useMatches();
  const { hasAccess } = useAccess();
  const { whoAmI } = useWhoAmI();

  const permissionNeeded = matches.flatMap(({ handle }) => {
    if (
      typeof handle !== "object" ||
      handle === null ||
      !hasProp(handle, "access")
    ) {
      return [];
    }

    if (Array.isArray(handle.access)) {
      return handle.access as AccessType[];
    }

    return [handle.access] as AccessType[];
  });

  if (whoAmI.isEmpty()) {
    return <KeycloakSpinner />;
  }

  if (!hasAccess(...permissionNeeded)) {
    return <ForbiddenSection permissionNeeded={permissionNeeded} />;
  }

  return children;
};
