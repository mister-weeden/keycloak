import type GroupRepresentation from "@mister-weeden/keycloak-admin-client/lib/defs/groupRepresentation";
import type RealmRepresentation from "@mister-weeden/keycloak-admin-client/lib/defs/realmRepresentation";
import { UserProfileMetadata } from "@mister-weeden/keycloak-admin-client/lib/defs/userProfileMetadata";
import type UserRepresentation from "@mister-weeden/keycloak-admin-client/lib/defs/userRepresentation";
import {
  FormErrorText,
  HelpItem,
  SwitchControl,
  TextControl,
  UserProfileFields,
} from "@mister-weeden/keycloak-ui-shared";
import {
  AlertVariant,
  Button,
  Chip,
  ChipGroup,
  FormGroup,
  InputGroup,
  InputGroupItem,
  Switch,
  TextInput,
} from "@patternfly/react-core";
import { TFunction } from "i18next";
import { useEffect, useState } from "react";
import { Controller, FormProvider, UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { useAdminClient } from "../admin-client";
import { DefaultSwitchControl } from "../components/SwitchControl";
import { useAlerts } from "@mister-weeden/keycloak-ui-shared";
import { FormAccess } from "../components/form/FormAccess";
import { GroupPickerDialog } from "../components/group/GroupPickerDialog";
import { useAccess } from "../context/access/Access";
import { useWhoAmI } from "../context/whoami/WhoAmI";
import { emailRegexPattern } from "../util";
import useFormatDate from "../utils/useFormatDate";
import { FederatedUserLink } from "./FederatedUserLink";
import { UserFormFields, toUserFormFields } from "./form-state";
import { toUsers } from "./routes/Users";
import { FixedButtonsGroup } from "../components/form/FixedButtonGroup";
import { RequiredActionMultiSelect } from "./user-credentials/RequiredActionMultiSelect";
import { useNavigate } from "react-router-dom";
import { CopyToClipboardButton } from "../components/copy-to-clipboard-button/CopyToClipboardButton";

export type BruteForced = {
  isBruteForceProtected?: boolean;
  isLocked?: boolean;
};

export type UserFormProps = {
  form: UseFormReturn<UserFormFields>;
  realm: RealmRepresentation;
  user?: UserRepresentation;
  bruteForce?: BruteForced;
  userProfileMetadata?: UserProfileMetadata;
  save: (user: UserFormFields) => void;
  refresh?: () => void;
  onGroupsUpdate?: (groups: GroupRepresentation[]) => void;
};

export const UserForm = ({
  form,
  realm,
  user,
  bruteForce: { isBruteForceProtected, isLocked } = {
    isBruteForceProtected: false,
    isLocked: false,
  },
  userProfileMetadata,
  save,
  refresh,
  onGroupsUpdate,
}: UserFormProps) => {
  const { adminClient } = useAdminClient();

  const { t } = useTranslation();
  const formatDate = useFormatDate();
  const { addAlert, addError } = useAlerts();
  const { hasAccess } = useAccess();
  const isManager = hasAccess("manage-users");
  const canViewFederationLink = hasAccess("view-realm");
  const { whoAmI } = useWhoAmI();
  const currentLocale = whoAmI.getLocale();

  const { handleSubmit, setValue, control, reset, formState } = form;
  const { errors } = formState;

  const [selectedGroups, setSelectedGroups] = useState<GroupRepresentation[]>(
    [],
  );
  const [open, setOpen] = useState(false);
  const [locked, setLocked] = useState(isLocked);
  const navigate = useNavigate();

  useEffect(() => {
    setValue("requiredActions", user?.requiredActions || []);
  }, [user, setValue]);

  const unLockUser = async () => {
    try {
      await adminClient.users.update({ id: user!.id! }, { enabled: true });
      addAlert(t("unlockSuccess"), AlertVariant.success);
      if (refresh) {
        refresh();
      }
    } catch (error) {
      addError("unlockError", error);
    }
  };

  const deleteItem = (id: string) => {
    setSelectedGroups(selectedGroups.filter((item) => item.name !== id));
    onGroupsUpdate?.(selectedGroups);
  };

  const addChips = async (groups: GroupRepresentation[]): Promise<void> => {
    setSelectedGroups([...selectedGroups!, ...groups]);
    onGroupsUpdate?.([...selectedGroups!, ...groups]);
  };

  const addGroups = async (groups: GroupRepresentation[]): Promise<void> => {
    const newGroups = groups;

    newGroups.forEach(async (group) => {
      try {
        await adminClient.users.addToGroup({
          id: user!.id!,
          groupId: group.id!,
        });
        addAlert(t("addedGroupMembership"), AlertVariant.success);
      } catch (error) {
        addError("addedGroupMembershipError", error);
      }
    });
  };

  const toggleModal = () => {
    setOpen(!open);
  };

  const onFormReset = () => {
    if (user?.id) {
      reset(toUserFormFields(user));
    } else {
      navigate(toUsers({ realm: realm.realm! }));
    }
  };

  const allFieldsReadOnly = () =>
    user?.userProfileMetadata?.attributes &&
    !user?.userProfileMetadata?.attributes
      ?.map((a) => a.readOnly)
      .reduce((p, c) => p && c, true);

  return (
    <FormAccess
      isHorizontal
      onSubmit={handleSubmit(save)}
      role="query-users"
      fineGrainedAccess={user?.access?.manage}
      className="pf-v5-u-mt-lg"
    >
      <FormProvider {...form}>
        {open && (
          <GroupPickerDialog
            type="selectMany"
            text={{
              title: "selectGroups",
              ok: "join",
            }}
            canBrowse={isManager}
            onConfirm={(groups) => {
              if (user?.id) {
                addGroups(groups || []);
              } else {
                addChips(groups || []);
              }

              setOpen(false);
            }}
            onClose={() => setOpen(false)}
            filterGroups={selectedGroups}
          />
        )}
        {user?.id && (
          <>
            <FormGroup label={t("id")} fieldId="kc-id" isRequired>
              <InputGroup>
                <InputGroupItem isFill>
                  <TextInput
                    id={user.id}
                    aria-label={t("userID")}
                    value={user.id}
                    readOnly
                  />
                </InputGroupItem>
                <InputGroupItem>
                  <CopyToClipboardButton
                    id={`user-${user.id}`}
                    text={user.id}
                    label={t("userID")}
                    variant="control"
                  />
                </InputGroupItem>
              </InputGroup>
            </FormGroup>
            <FormGroup
              label={t("createdAt")}
              fieldId="kc-created-at"
              isRequired
            >
              <TextInput
                value={formatDate(new Date(user.createdTimestamp!))}
                id="kc-created-at"
                readOnly
              />
            </FormGroup>
          </>
        )}
        <RequiredActionMultiSelect
          name="requiredActions"
          label="requiredUserActions"
          help="requiredUserActionsHelp"
        />
        {user?.federationLink && canViewFederationLink && (
          <FormGroup
            label={t("federationLink")}
            labelIcon={
              <HelpItem
                helpText={t("federationLinkHelp")}
                fieldLabelId="federationLink"
              />
            }
          >
            <FederatedUserLink user={user} />
          </FormGroup>
        )}
        {userProfileMetadata ? (
          <>
            <DefaultSwitchControl
              name="emailVerified"
              label={t("emailVerified")}
              labelIcon={t("emailVerifiedHelp")}
            />
            <UserProfileFields
              form={form}
              userProfileMetadata={userProfileMetadata}
              hideReadOnly={!user}
              supportedLocales={realm.supportedLocales || []}
              currentLocale={currentLocale}
              t={
                ((key: unknown, params) =>
                  t(key as string, params as any)) as TFunction
              }
            />
          </>
        ) : (
          <>
            {!realm.registrationEmailAsUsername && (
              <TextControl
                name="username"
                label={t("username")}
                readOnly={
                  !!user?.id &&
                  !realm.editUsernameAllowed &&
                  realm.editUsernameAllowed !== undefined
                }
                rules={{
                  required: t("required"),
                }}
              />
            )}
            <TextControl
              name="email"
              label={t("email")}
              type="email"
              rules={{
                pattern: {
                  value: emailRegexPattern,
                  message: t("emailInvalid"),
                },
              }}
            />
            <SwitchControl
              name="emailVerified"
              label={t("emailVerified")}
              labelIcon={t("emailVerifiedHelp")}
              labelOn={t("yes")}
              labelOff={t("no")}
            />
            <TextControl name="firstName" label={t("firstName")} />
            <TextControl name="lastName" label={t("lastName")} />
          </>
        )}
        {isBruteForceProtected && (
          <FormGroup
            label={t("temporaryLocked")}
            fieldId="temporaryLocked"
            labelIcon={
              <HelpItem
                helpText={t("temporaryLockedHelp")}
                fieldLabelId="temporaryLocked"
              />
            }
          >
            <Switch
              data-testid="user-locked-switch"
              id="temporaryLocked"
              onChange={(_event, value) => {
                unLockUser();
                setLocked(value);
              }}
              isChecked={locked}
              isDisabled={!locked}
              label={t("on")}
              labelOff={t("off")}
            />
          </FormGroup>
        )}
        {!user?.id && (
          <FormGroup
            label={t("groups")}
            fieldId="kc-groups"
            labelIcon={
              <HelpItem helpText={t("groupsHelp")} fieldLabelId="groups" />
            }
          >
            <Controller
              name="groups"
              defaultValue={[]}
              control={control}
              render={() => (
                <InputGroup>
                  <InputGroupItem>
                    <ChipGroup categoryName={" "}>
                      {selectedGroups.map((currentChip) => (
                        <Chip
                          key={currentChip.id}
                          onClick={() => deleteItem(currentChip.name!)}
                        >
                          {currentChip.path}
                        </Chip>
                      ))}
                    </ChipGroup>
                  </InputGroupItem>
                  <InputGroupItem>
                    <Button
                      id="kc-join-groups-button"
                      onClick={toggleModal}
                      variant="secondary"
                      data-testid="join-groups-button"
                    >
                      {t("joinGroups")}
                    </Button>
                  </InputGroupItem>
                </InputGroup>
              )}
            />
            {errors.requiredActions && (
              <FormErrorText message={t("required")} />
            )}
          </FormGroup>
        )}
      </FormProvider>
      <FixedButtonsGroup
        name="user-creation"
        saveText={user?.id ? t("save") : t("create")}
        reset={onFormReset}
        resetText={user?.id ? t("revert") : t("cancel")}
        isDisabled={allFieldsReadOnly()}
        isSubmit
      />
    </FormAccess>
  );
};
