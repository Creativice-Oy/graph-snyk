import {
  IntegrationExecutionContext,
  PersisterOperationsResult,
} from "@jupiterone/jupiter-managed-integration-sdk";
import SnykClient from "@jupiterone/snyk-client";
import { SNYK_SERVICE_ENTITY_TYPE } from "./constants";
import {
  Project,
  toCodeRepoEntity,
  toCodeRepoFindingRelationship,
  toCVEEntities,
  toCWEEntities,
  toFindingEntity,
  toFindingVulnerabilityRelationship,
  toFindingWeaknessRelationship,
  toServiceCodeRepoRelationship,
  Vulnerability,
} from "./converters";
import { createOperationsFromFindings } from "./createOperations";
import {
  CodeRepoEntity,
  CodeRepoFindingRelationship,
  FindingCWERelationship,
  FindingEntity,
  FindingVulnerabilityRelationship,
  ServiceCodeRepoRelationship,
  ServiceEntity,
  SnykIntegrationInstanceConfig,
} from "./types";

export default async function synchronize(
  context: IntegrationExecutionContext,
): Promise<PersisterOperationsResult> {
  const { persister } = context.clients.getClients();
  const config = context.instance.config as SnykIntegrationInstanceConfig;
  const Snyk = new SnykClient(config.snykApiKey, config.snykOrgId);
  const service: ServiceEntity = {
    _key: `hackerone:${config.snykOrgId}`,
    _type: SNYK_SERVICE_ENTITY_TYPE,
    _class: ["Service", "Assessment"],
    displayName: `Snyk Scanner for ${config.snykOrgId}`,
    category: "snyk",
    handle: config.snykApiKey,
  };

  const serviceCodeRepoRelationships: ServiceCodeRepoRelationship[] = [];
  const codeRepoFindingRelationships: CodeRepoFindingRelationship[] = [];
  const findingVulnerabilityRelationships: FindingVulnerabilityRelationship[] = [];
  const findingCWERelationships: FindingCWERelationship[] = [];
  const serviceEntities: ServiceEntity[] = [service];
  const codeRepoEntities: CodeRepoEntity[] = [];
  const findingEntities: FindingEntity[] = [];

  let allProjects: Project[] = (await Snyk.listAllProjects(config.snykOrgId))
    .projects;
  allProjects = allProjects.filter(
    project => project.origin === "bitbucket-cloud",
  );
  // allProjects = allProjects.slice(10, 15); // shorten for testing purposes

  for (const project of allProjects) {
    const proj: CodeRepoEntity = toCodeRepoEntity(project);
    codeRepoEntities.push(proj);
    serviceCodeRepoRelationships.push(
      toServiceCodeRepoRelationship(service, proj),
    );

    const vulnerabilities: Vulnerability[] = (await Snyk.listIssues(
      config.snykOrgId,
      project.id,
      {},
    )).issues.vulnerabilities;
    vulnerabilities.forEach((vulnerability: Vulnerability) => {
      const finding: FindingEntity = toFindingEntity(vulnerability);
      findingEntities.push(finding);
      codeRepoFindingRelationships.push(
        toCodeRepoFindingRelationship(proj, finding),
      );

      const cveList = toCVEEntities(vulnerability);
      for (const cve of cveList) {
        findingVulnerabilityRelationships.push(
          toFindingVulnerabilityRelationship(finding, cve),
        );
      }

      const cweList = toCWEEntities(vulnerability);
      for (const cwe of cweList) {
        findingCWERelationships.push(
          toFindingWeaknessRelationship(finding, cwe),
        );
      }
    });
  }

  return persister.publishPersisterOperations(
    await createOperationsFromFindings(
      context,
      serviceEntities,
      codeRepoEntities,
      findingEntities,
      serviceCodeRepoRelationships,
      codeRepoFindingRelationships,
      findingVulnerabilityRelationships,
      findingCWERelationships,
    ),
  );
}