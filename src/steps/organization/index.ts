import {
  createDirectRelationship,
  Entity,
  IntegrationStep,
  IntegrationStepExecutionContext,
  RelationshipClass,
} from '@jupiterone/integration-sdk-core';
import { IntegrationConfig } from '../../config';
import { Entities, Relationships, SetDataKeys, StepIds } from '../../constants';
import { createOrganizationEntity } from '../../converters';
import { APIClient } from '../../snyk/client';

async function fetchOrganizations({
  instance,
  jobState,
  logger,
}: IntegrationStepExecutionContext<IntegrationConfig>) {
  const apiClient = new APIClient(logger, instance.config);
  const groupEntity = (await jobState.getData(
    SetDataKeys.GROUP_ENTITY,
  )) as Entity;

  await apiClient.iterateOrganizations(async (organization) => {
    const organizationEntity = await jobState.addEntity(
      createOrganizationEntity(organization),
    );

    await jobState.addRelationship(
      createDirectRelationship({
        _class: RelationshipClass.HAS,
        from: groupEntity,
        to: organizationEntity,
      }),
    );
  });
}

export const organizationStep: IntegrationStep<IntegrationConfig>[] = [
  {
    id: StepIds.FETCH_ORGANIZATIONS,
    name: 'Fetch Organizations',
    entities: [Entities.ORGANIZATION],
    relationships: [Relationships.GROUP_ORGANIZATION],
    dependsOn: [StepIds.FETCH_GROUP],
    executionHandler: fetchOrganizations,
  },
];
