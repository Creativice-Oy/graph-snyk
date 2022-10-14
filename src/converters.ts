import {
  createIntegrationEntity,
  Entity,
  parseTimePropertyValue,
  Relationship,
  RelationshipDirection,
} from '@jupiterone/integration-sdk-core';
import { Entities, Relationships } from './constants';

import {
  Account,
  CVEEntity,
  CWEEntity,
  Group,
  Organization,
  Role,
  Service,
} from './types';

import startCase from 'lodash.startcase';

const CVE_URL_BASE = 'https://nvd.nist.gov/vuln/detail/';

export function createAccountEntity(data: Account): Entity {
  return createIntegrationEntity({
    entityData: {
      source: data,
      assign: {
        _key: `snyk:${data.id}`,
        _type: Entities.SNYK_ACCOUNT._type,
        _class: Entities.SNYK_ACCOUNT._class,
        id: data.id,
        description: data.description,
        name: data.name,
      },
    },
  });
}

export function createServiceEntity(service: Service): Entity {
  return createIntegrationEntity({
    entityData: {
      source: {},
      assign: {
        _key: `snyk_service`,
        _type: Entities.SNYK_SERVICE._type,
        _class: Entities.SNYK_SERVICE._class,
        category: ['security'],
        name: service.name,
        displayName: service.name,
        function: ['scanning'],
      },
    },
  });
}

export function createGroupEntity(group: Group): Entity {
  return createIntegrationEntity({
    entityData: {
      source: group,
      assign: {
        _key: `snyk_group:${group.id}`,
        _type: Entities.GROUP._type,
        _class: Entities.GROUP._class,
        id: group.id,
        name: group.name,
        webLink: group.url,
      },
    },
  });
}

export function createOrganizationEntity(org: Organization): Entity {
  return createIntegrationEntity({
    entityData: {
      source: org,
      assign: {
        _key: `snyk_org:${org.id}`,
        _type: Entities.ORGANIZATION._type,
        _class: Entities.ORGANIZATION._class,
        id: org.id,
        name: org.name,
        webLink: org.url,
        displayName: org.slug,
        createdOn: parseTimePropertyValue(org.created),
      },
    },
  });
}

const SEVERITY_TO_NUMERIC_SEVERITY_MAP = new Map<string, number>([
  ['low', 2],
  ['medium', 5],
  ['high', 7],
  ['critical', 10],
]);

export function getNumericSeverityFromIssueSeverity(
  issueSeverity?: 'low' | 'medium' | 'high' | 'critical',
): number {
  if (!issueSeverity) return 0;

  const numericSeverity = SEVERITY_TO_NUMERIC_SEVERITY_MAP.get(issueSeverity);
  return numericSeverity === undefined ? 0 : numericSeverity;
}

export function createFindingEntity(vuln: any) {
  return createIntegrationEntity({
    entityData: {
      source: vuln,
      assign: {
        _class: Entities.SNYK_FINDING._class,
        _key: `snyk-project-${vuln.projectId}-vuln-${vuln.id}`,
        _type: Entities.SNYK_FINDING._type,
        category: 'application',
        score: vuln.issueData.cvssScore || undefined,
        cvssScore: vuln.issueData.cvssScore,
        cwe: vuln.issueData.identifiers?.CWE,
        cve: vuln.issueData.identifiers?.CVE,
        description: vuln.issueData.description,
        name: vuln.issueData.title,
        displayName: vuln.issueData.title,
        webLink: vuln.issueData.url,
        id: vuln.id,
        numericSeverity: getNumericSeverityFromIssueSeverity(
          vuln.issueData.severity,
        ),
        severity: startCase(vuln.issueData.severity), // Severity after policies have been applied
        originalSeverity: vuln.issueData.originalSeverity, // Severity as seen in snyk DB, before policies have been applied
        pkgName: vuln.pkgName,
        pkgVersions: vuln.pkgVersions,
        language: vuln.issueData.language,
        isUpgradable: vuln.fixInfo?.isUpgradable,
        isPatchable: vuln.fixInfo?.isPatchable,
        isPinnable: vuln.fixInfo?.isPinnable,
        isFixable: vuln.fixInfo?.isFixable,
        isPartiallyFixable: vuln.fixInfo?.isPartiallyFixable,
        fixedIn: vuln.fixInfo?.fixedIn,

        publicationTime: parseTimePropertyValue(vuln.issueData.publicationTime),
        disclosureTime: parseTimePropertyValue(vuln.issueData.disclosureTime),
        open: true,
        targets: [],
        issueType: vuln.issueType,
        identifiedInFile: '',

        priorityScore: vuln.priorityScore,
        exploitMaturity: vuln.exploitMaturity,
        nearestFixedInVersion: vuln.nearestFixedInVersion,
        isMaliciousPackage: vuln.isMaliciousPackage,
        isPatched: vuln.isPatched,
        isIgnored: vuln.isIgnored,
        violatedPolicyPublicId: vuln.issueData.violatedPolicyPublicId,

        path: vuln.issueData.path,
      },
    },
  });
}

export function createRoleEntity(role: Role): Entity {
  return createIntegrationEntity({
    entityData: {
      source: role,
      assign: {
        _key: `snyk_role:${role.name.split(' ')[1].toLowerCase()}`,
        _type: Entities.ROLE._type,
        _class: Entities.ROLE._class,
        name: role.name,
        description: role.description,
        publicId: role.publicId,
        createdOn: parseTimePropertyValue(role.created),
        modified: parseTimePropertyValue(role.modified),
      },
    },
  });
}

export function createCVEEntity(
  cve: string,
  cvssScore: number | string,
): CVEEntity {
  const cveLowerCase = cve.toLowerCase();
  const cveUpperCase = cve.toUpperCase();
  const link = CVE_URL_BASE + cveUpperCase;
  return {
    _class: Entities.CVE._class,
    _key: cveLowerCase,
    _type: Entities.CVE._type,
    name: cveUpperCase,
    displayName: cveUpperCase,
    cvssScore: cvssScore,
    references: [link],
    webLink: link,
  };
}

export function createCWEEntity(cwe: string): CWEEntity {
  const cweLowerCase = cwe.toLowerCase();
  const cweUpperCase = cwe.toUpperCase();
  const link = `https://cwe.mitre.org/data/definitions/${
    cwe.split('-')[1]
  }.html`;
  return {
    _class: Entities.CWE._class,
    _key: cweLowerCase,
    _type: Entities.CWE._type,
    name: cweUpperCase,
    displayName: cweUpperCase,
    references: [link],
    webLink: link,
  };
}

export function createOrganizationFindingRelationship(
  organization: Entity,
  finding: Entity,
): Relationship {
  return {
    _class: 'IDENTIFIED',
    _key: `${organization._key}|identified|${finding._key}`,
    _type: Relationships.ORGANIZATION_IDENTIFIED_FINDING._type,
    _fromEntityKey: organization._key,
    _toEntityKey: finding._key,
    displayName: 'IDENTIFIED',
  };
}

export function createFindingVulnerabilityRelationship(
  finding: Entity,
  cve: CVEEntity,
): Relationship {
  return {
    _key: `${finding._key}|is|${cve._key}`,
    _class: 'IS',
    _type: Relationships.FINDING_IS_CVE._type,
    _mapping: {
      sourceEntityKey: finding._key,
      relationshipDirection: RelationshipDirection.FORWARD,
      targetFilterKeys: [['_type', '_key']],
      targetEntity: cve,
    },
    displayName: 'IS',
  };
}

export function createFindingWeaknessRelationship(
  finding: Entity,
  cwe: CWEEntity,
): Relationship {
  return {
    _key: `${finding._key}|is|${cwe._key}`,
    _class: 'EXPLOITS',
    _type: Relationships.FINDING_EXPLOITS_CWE._type,
    _mapping: {
      sourceEntityKey: finding._key,
      relationshipDirection: RelationshipDirection.FORWARD,
      targetFilterKeys: [['_type', '_key']],
      targetEntity: cwe,
    },
    displayName: 'EXPLOITS',
  };
}
