import {
  createDirectRelationship,
  Entity,
  getRawData,
  IntegrationStep,
  IntegrationStepExecutionContext,
  RelationshipClass,
} from '@jupiterone/integration-sdk-core';

import { APIClient } from '../snyk/client';
import { IntegrationConfig } from '../config';
import { Entities, Relationships, StepIds } from '../constants';
import {
  createCVEEntity,
  createCWEEntity,
  createFindingEntity,
  createFindingVulnerabilityRelationship,
  createFindingWeaknessRelationship,
  createOrganizationFindingRelationship,
} from '../converters';
import { FindingEntity, Project } from '../types';

async function fetchFindings({
  jobState,
  instance,
  logger,
}: IntegrationStepExecutionContext<IntegrationConfig>) {
  const apiClient = new APIClient(logger, instance.config);

  let totalFindingsEncountered = 0;
  let totalCriticalFindingsEncountered = 0;
  let totalHighFindingsEncountered = 0;
  let totalMediumFindingsEncountered = 0;
  let totalLowFindingsEncountered = 0;

  await jobState.iterateEntities(
    {
      _type: Entities.PROJECT._type,
    },
    async (projectEntity) => {
      const projectId = projectEntity.id as string | undefined;
      const projectName = projectEntity.name as string | undefined;

      const project = getRawData<Project & { orgId: string }>(projectEntity);
      if (!project) {
        `Can not get raw data for entity ${projectEntity._key}`;
        return;
      }

      const organizationEntity = (await jobState.findEntity(
        `snyk_org:${project?.orgId}`,
      )) as Entity;

      if (!projectId || !projectName) return;
      const [, packageName] = projectName.split(':');

      await apiClient.iterateIssues(projectId, async (issue) => {
        const finding = createFindingEntity({
          ...issue,
          projectId,
        }) as FindingEntity;
        totalFindingsEncountered++;

        if (finding.severity === 'critical') {
          totalCriticalFindingsEncountered++;
        } else if (finding.severity === 'high') {
          totalHighFindingsEncountered++;
        } else if (finding.severity === 'medium') {
          totalMediumFindingsEncountered++;
        } else if (finding.severity === 'low') {
          totalLowFindingsEncountered++;
        }

        finding.identifiedInFile = packageName;

        for (const cve of finding.cve || []) {
          const cveEntity = createCVEEntity(cve, issue.issueData.cvssScore!);
          await jobState.addRelationship(
            createFindingVulnerabilityRelationship(finding, cveEntity),
          );
        }

        for (const cwe of finding.cwe || []) {
          const cweEntity = createCWEEntity(cwe);
          await jobState.addRelationship(
            createFindingWeaknessRelationship(finding, cweEntity),
          );
        }

        await jobState.addRelationship(
          createOrganizationFindingRelationship(organizationEntity, finding),
        );

        await jobState.addEntity(finding);

        const projectHasFindingRelationship = createDirectRelationship({
          from: projectEntity,
          to: finding,
          _class: RelationshipClass.HAS,
        });

        if (!jobState.hasKey(projectHasFindingRelationship._key)) {
          await jobState.addRelationship(projectHasFindingRelationship);
        }
      });
    },
  );

  logger.info(
    {
      totalFindingsEncountered,
      totalCriticalFindingsEncountered,
      totalHighFindingsEncountered,
      totalMediumFindingsEncountered,
      totalLowFindingsEncountered,
    },
    'Finding Entity Counts Summary',
  );
}

export const steps: IntegrationStep<IntegrationConfig>[] = [
  {
    id: StepIds.FETCH_FINDINGS,
    name: 'Fetch findings',
    entities: [Entities.CVE, Entities.CWE, Entities.SNYK_FINDING],
    relationships: [
      Relationships.FINDING_IS_CVE,
      Relationships.FINDING_EXPLOITS_CWE,
      Relationships.ORGANIZATION_IDENTIFIED_FINDING,
      Relationships.PROJECT_FINDING,
    ],
    dependsOn: [StepIds.FETCH_ORGANIZATIONS, StepIds.FETCH_PROJECTS],
    executionHandler: fetchFindings,
  },
];
