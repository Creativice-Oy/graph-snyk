import {
  createDirectRelationship,
  Entity,
  getRawData,
  IntegrationStep,
  IntegrationStepExecutionContext,
  RelationshipClass,
} from '@jupiterone/integration-sdk-core';
import { IntegrationConfig } from '../../config';
import { Entities, Relationships, SetDataKeys, StepIds } from '../../constants';
import { createRoleEntity } from '../../converters';
import { APIClient } from '../../snyk/client';
import { User } from '../../types';

async function fetchRoles({
  instance,
  jobState,
  logger,
}: IntegrationStepExecutionContext<IntegrationConfig>) {
  const apiClient = new APIClient(logger, instance.config);
  const groupEntity = (await jobState.getData(
    SetDataKeys.GROUP_ENTITY,
  )) as Entity;

  await apiClient.iterateRoles(async (role) => {
    const roleEntity = await jobState.addEntity(createRoleEntity(role));

    await jobState.addRelationship(
      createDirectRelationship({
        _class: RelationshipClass.HAS,
        from: groupEntity,
        to: roleEntity,
      }),
    );
  });
}

async function buildUserRoleRelationship({
  jobState,
  logger,
}: IntegrationStepExecutionContext<IntegrationConfig>) {
  await jobState.iterateEntities(
    { _type: Entities.USER._type },
    async (userEntity) => {
      const user = getRawData<User>(userEntity);
      if (!user) {
        logger.warn(
          { _key: userEntity._key },
          'Could not get raw data for user entity',
        );
        return;
      }

      const roleEntity = (await jobState.findEntity(
        `snyk_role:${user.role}`,
      )) as Entity;

      if (roleEntity) {
        await jobState.addRelationship(
          createDirectRelationship({
            _class: RelationshipClass.ASSIGNED,
            from: userEntity,
            to: roleEntity,
          }),
        );
      }
    },
  );
}

export const roleStep: IntegrationStep<IntegrationConfig>[] = [
  {
    id: StepIds.FETCH_ROLES,
    name: 'Fetch Roles',
    entities: [Entities.ROLE],
    relationships: [Relationships.GROUP_ROLE],
    dependsOn: [StepIds.FETCH_GROUP],
    executionHandler: fetchRoles,
  },
  {
    id: StepIds.BUILD_USER_ROLE,
    name: 'Build User and Role Relationship',
    entities: [],
    relationships: [Relationships.USER_ROLE],
    dependsOn: [StepIds.FETCH_ROLES, StepIds.FETCH_USERS],
    executionHandler: buildUserRoleRelationship,
  },
];
