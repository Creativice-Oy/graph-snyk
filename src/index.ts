import { IntegrationInvocationConfig } from '@jupiterone/integration-sdk-core';

import {
  IntegrationConfig,
  instanceConfigFields,
  validateInvocation,
} from './config';
import { steps as projectSteps } from './steps/projects';
import { steps as findingSteps } from './steps/fetchFindings';
import { steps as userSteps } from './steps/users';
import { groupStep } from './steps/group';
import { organizationStep } from './steps/organization';
import { roleStep } from './steps/roles';

export const invocationConfig: IntegrationInvocationConfig<IntegrationConfig> = {
  instanceConfigFields,
  validateInvocation,
  integrationSteps: [
    ...projectSteps,
    ...findingSteps,
    ...userSteps,
    ...groupStep,
    ...organizationStep,
    ...roleStep,
  ],
};
