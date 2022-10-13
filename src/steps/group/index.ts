import {
  IntegrationStep,
  IntegrationStepExecutionContext,
} from '@jupiterone/integration-sdk-core';
import { IntegrationConfig } from '../../config';
import { Entities, SetDataKeys, StepIds } from '../../constants';
import { createGroupEntity } from '../../converters';
import { APIClient } from '../../snyk/client';

async function fetchGroup({
  instance,
  jobState,
  logger,
}: IntegrationStepExecutionContext<IntegrationConfig>) {
  const apiClient = new APIClient(logger, instance.config);

  const groupEntity = await jobState.addEntity(
    createGroupEntity(await apiClient.getGroupDetails()),
  );
  await jobState.setData(SetDataKeys.GROUP_ENTITY, groupEntity);
}

export const groupStep: IntegrationStep<IntegrationConfig>[] = [
  {
    id: StepIds.FETCH_GROUP,
    name: 'Fetch Group',
    entities: [Entities.GROUP],
    relationships: [],
    executionHandler: fetchGroup,
  },
];
