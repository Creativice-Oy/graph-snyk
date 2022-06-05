import { createStepCollectionTest } from '../../../test/recording';
import { StepIds } from '../../constants';

test(
  'fetch-projects',
  createStepCollectionTest({
    directoryName: __dirname,
    recordingName: 'fetch-projects',
    stepId: StepIds.FETCH_PROJECTS,
  }),
);
