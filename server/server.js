const express = require('express');
const path = require('path');
const { execSync } = require('child_process');

const app = express();
const PORT = 3421;

app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

// ───────────────────────────────────────────
// Azure CLI token auth (no app registration needed)
// ───────────────────────────────────────────
function getAzToken() {
  let out;
  try {
    out = execSync('az account get-access-token --resource https://management.azure.com -o json', { encoding: 'utf8' });
  } catch (e) {
    throw new Error('Azure CLI not available or not logged in. Open a terminal, run "az login", then try again.');
  }
  return JSON.parse(out).accessToken;
}

async function armGet(url, token) {
  const r = await fetch(url, { headers: { Authorization: `Bearer ${token}`, 'Accept-Language': 'en-US' } });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error?.message || `ARM GET failed (${r.status}): ${JSON.stringify(body)}`);
  return body;
}

async function armPatch(url, token, payload) {
  const r = await fetch(url, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', 'Accept-Language': 'en-US' },
    body: JSON.stringify(payload),
  });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error?.message || `ARM PATCH failed (${r.status}): ${JSON.stringify(body)}`);
  return body;
}

async function armPost(url, token, payload) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', 'Accept-Language': 'en-US' },
    body: JSON.stringify(payload || {}),
  });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error?.message || `ARM POST failed (${r.status}): ${JSON.stringify(body)}`);
  return body;
}

async function armPut(url, token, payload) {
  const r = await fetch(url, {
    method: 'PUT',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', 'Accept-Language': 'en-US' },
    body: JSON.stringify(payload),
  });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error?.message || `ARM PUT failed (${r.status}): ${JSON.stringify(body)}`);
  return body;
}

// ───────────────────────────────────────────
// Remediation guidance
// ───────────────────────────────────────────
const REMEDIATION = {
  'Required tags on resources': "Apply required tags (Environment, Owner, CostCenter) to non-compliant resources - use the 'Apply tags' action on this page, or assign an Azure Policy with a 'modify'/'deny' effect to enforce tagging going forward.",
  'Azure Policy / initiative assignments': 'Assign the landing zone / CAF baseline initiative (e.g. Azure Security Benchmark) at the management group or subscription scope.',
  'Resource locks (CanNotDelete)': 'Add CanNotDelete locks on critical resource groups (networking, shared services, production).',
  'Permanent Owner/Contributor at subscription scope': 'Remove standing Owner/Contributor assignments except for documented break-glass accounts; convert remaining access to PIM-eligible assignments.',
  'PIM eligible role assignments configured': 'Enable Microsoft Entra Privileged Identity Management for Azure resources and convert standing role assignments to eligible (time-bound) assignments.',
  'Defender for Cloud plans (Standard tier)': 'Enable Microsoft Defender for Cloud Standard tier on relevant resource types (Servers, Storage, Key Vault, SQL, etc.).',
  'Storage account security settings': "For each flagged storage account: enable 'Secure transfer required', set Minimum TLS version to 1.2, disable 'Allow Blob public access', and restrict network access.",
  'Key Vault soft delete & purge protection': 'Enable Soft Delete and Purge Protection on the flagged key vault(s) (cannot be disabled once enabled - plan accordingly).',
  'NSGs applied to all subnets': 'Create and associate a Network Security Group with each subnet listed, with explicit deny-by-default rules.',
  'Budgets configured': 'Create a budget at subscription scope with alert thresholds (Cost Management + Billing > Budgets).',
  'Management Group placement': 'Move the subscription under an appropriate management group in your management group hierarchy so policies and RBAC inherit consistently.',
  'DDoS Protection on VNets': 'Enable Azure DDoS Network Protection on VNets hosting internet-facing workloads.',
  'Private Endpoints for PaaS services': 'Create private endpoints for PaaS services (Storage, SQL, Key Vault, etc.) instead of relying on public endpoints.',
  'Activity Log exported to Log Analytics': 'Create a subscription-level diagnostic setting to export the Activity Log to a Log Analytics workspace for auditing and alerting.',
  'Recovery Services Vault with backup items': 'Create a Recovery Services Vault and configure backup policies for VMs and other supported workloads.',
  'VM auto-shutdown schedules': 'Configure auto-shutdown schedules on non-production VMs (Microsoft.DevTestLab/schedules) to reduce compute costs.',
  'Naming convention compliance': "Rename non-compliant resources/resource groups to follow CAF abbreviation conventions (e.g. rg-, st, kv, vnet, nsg, vm, pip, app, sql), or document an alternative naming standard.",
  'Allowed locations / SKU restriction policy': "Assign the built-in 'Allowed locations' and 'Allowed virtual machine SKUs' policies at subscription or management group scope.",
  'Policy compliance state': 'Review non-compliant resources in Azure Policy > Compliance and remediate via policy remediation tasks.',
  'Reserved Instance / Savings Plan coverage': 'Review steady-state compute/database usage and purchase Reserved Instances or Savings Plans for cost optimization.',
  'Regulatory compliance (Defender for Cloud)': 'Review failed controls under the assigned regulatory standards in Defender for Cloud > Regulatory compliance and remediate.',
};

const ROLE_IDS = {
  Owner: '8e3af657-a8ff-443c-a75c-2fe8c4bcb635',
  Contributor: 'b24988ac-6180-42a0-ab88-20f7382dd24c',
};

function result(category, check, status, details, extra) {
  const recommendation = ['Not Implemented', 'Partial', 'Error'].includes(status) ? (REMEDIATION[check] || '') : '';
  return { category, check, status, details, recommendation, ...(extra ? { extra } : {}) };
}

// ───────────────────────────────────────────
// Checks (CAF-aligned, MVP set of 10)
// ───────────────────────────────────────────
const CHECKS = [
  {
    category: 'Governance & Tagging',
    check: 'Required tags on resources',
    run: async (token, subId) => {
      const requiredTags = ['Environment', 'Owner', 'CostCenter'];
      const body = await armGet(`https://management.azure.com/subscriptions/${subId}/resources?api-version=2021-04-01`, token);
      const resources = body.value || [];
      if (resources.length === 0) {
        return result('Governance & Tagging', 'Required tags on resources', 'Manual / Process', 'No resources found in subscription');
      }
      const missing = resources.filter(r => {
        const tags = r.tags || {};
        return requiredTags.some(t => !(t in tags));
      });
      const pct = Math.round(((resources.length - missing.length) / resources.length) * 1000) / 10;
      const nonCompliant = missing.map(r => ({ id: r.id, name: r.name, type: r.type, tags: r.tags || {} }));
      if (missing.length === 0) {
        return result('Governance & Tagging', 'Required tags on resources', 'Implemented', `All ${resources.length} resources tagged with ${requiredTags.join(', ')}`);
      } else if (missing.length < resources.length) {
        return result('Governance & Tagging', 'Required tags on resources', 'Partial', `${pct}% compliant. ${missing.length} of ${resources.length} resources missing one or more of: ${requiredTags.join(', ')}`, { nonCompliant });
      } else {
        return result('Governance & Tagging', 'Required tags on resources', 'Not Implemented', `0 of ${resources.length} resources have required tags (${requiredTags.join(', ')})`, { nonCompliant });
      }
    },
  },
  {
    category: 'Governance & Tagging',
    check: 'Azure Policy / initiative assignments',
    run: async (token, subId) => {
      const body = await armGet(`https://management.azure.com/subscriptions/${subId}/providers/Microsoft.Authorization/policyAssignments?api-version=2022-06-01`, token);
      const assignments = body.value || [];
      if (assignments.length === 0) {
        return result('Governance & Tagging', 'Azure Policy / initiative assignments', 'Not Implemented', 'No policy/initiative assignments found at subscription scope');
      }
      const names = assignments.map(a => a.properties?.displayName || a.name).join('; ');
      return result('Governance & Tagging', 'Azure Policy / initiative assignments', 'Implemented', `${assignments.length} assignment(s): ${names}`);
    },
  },
  {
    category: 'Governance & Tagging',
    check: 'Resource locks (CanNotDelete)',
    run: async (token, subId) => {
      const [locksBody, rgsBody] = await Promise.all([
        armGet(`https://management.azure.com/subscriptions/${subId}/providers/Microsoft.Authorization/locks?api-version=2020-05-01`, token),
        armGet(`https://management.azure.com/subscriptions/${subId}/resourcegroups?api-version=2021-04-01`, token),
      ]);
      const locks = (locksBody.value || []).filter(l => l.properties?.level === 'CanNotDelete');
      const lockedRgNames = new Set(
        locks
          .map(l => (l.id.match(/\/resourceGroups\/([^/]+)\/providers\/Microsoft\.Authorization\/locks\//i) || [])[1])
          .filter(Boolean)
          .map(n => n.toLowerCase())
      );
      const resourceGroups = (rgsBody.value || []).map(rg => ({
        name: rg.name,
        locked: lockedRgNames.has(rg.name.toLowerCase()),
      }));
      const unlockedCount = resourceGroups.filter(rg => !rg.locked).length;

      if (locks.length > 0 && unlockedCount === 0) {
        return result('Governance & Tagging', 'Resource locks (CanNotDelete)', 'Implemented', `${locks.length} CanNotDelete lock(s) found - all ${resourceGroups.length} resource group(s) covered`, { resourceGroups });
      }
      if (locks.length > 0) {
        return result('Governance & Tagging', 'Resource locks (CanNotDelete)', 'Partial', `${locks.length} CanNotDelete lock(s) found, but ${unlockedCount} of ${resourceGroups.length} resource group(s) have none`, { resourceGroups });
      }
      return result('Governance & Tagging', 'Resource locks (CanNotDelete)', 'Not Implemented', 'No CanNotDelete locks found on any scope', { resourceGroups });
    },
  },
  {
    category: 'Identity & Access',
    check: 'Permanent Owner/Contributor at subscription scope',
    run: async (token, subId) => {
      const subScope = `/subscriptions/${subId}`;
      const body = await armGet(`https://management.azure.com${subScope}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01`, token);
      const assignments = (body.value || []).filter(a => {
        if (a.properties?.scope !== subScope) return false;
        const roleDefId = a.properties?.roleDefinitionId || '';
        return roleDefId.endsWith(ROLE_IDS.Owner) || roleDefId.endsWith(ROLE_IDS.Contributor);
      });
      if (assignments.length === 0) {
        return result('Identity & Access', 'Permanent Owner/Contributor at subscription scope', 'Implemented', 'No standing Owner/Contributor role assignments at subscription scope');
      }
      return result('Identity & Access', 'Permanent Owner/Contributor at subscription scope', 'Partial', `${assignments.length} standing assignment(s) found - verify these are break-glass accounts only`);
    },
  },
  {
    category: 'Identity & Access',
    check: 'PIM eligible role assignments configured',
    run: async (token, subId) => {
      const url = `https://management.azure.com/subscriptions/${subId}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01&$filter=asTarget()`;
      const body = await armGet(url, token);
      if (body.value && body.value.length > 0) {
        return result('Identity & Access', 'PIM eligible role assignments configured', 'Implemented', `${body.value.length} eligible PIM assignment(s) found for caller in this subscription`);
      }
      return result('Identity & Access', 'PIM eligible role assignments configured', 'Not Implemented', 'No PIM-eligible assignments found for caller (PIM for Azure resources may not be enabled, or caller has standing access only)');
    },
  },
  {
    category: 'Security Baseline',
    check: 'Defender for Cloud plans (Standard tier)',
    run: async (token, subId) => {
      const body = await armGet(`https://management.azure.com/subscriptions/${subId}/providers/Microsoft.Security/pricings?api-version=2024-01-01`, token);
      const pricings = body.value || [];
      const standard = pricings.filter(p => p.properties?.pricingTier === 'Standard');
      const free = pricings.filter(p => p.properties?.pricingTier !== 'Standard');
      const freePlans = free.map(p => p.name);
      if (standard.length === 0) {
        return result('Security Baseline', 'Defender for Cloud plans (Standard tier)', 'Not Implemented', 'All Defender plans are on Free tier', { freePlans });
      } else if (free.length === 0) {
        return result('Security Baseline', 'Defender for Cloud plans (Standard tier)', 'Implemented', `All Defender plans on Standard: ${standard.map(p => p.name).join(', ')}`);
      }
      return result('Security Baseline', 'Defender for Cloud plans (Standard tier)', 'Partial', `Standard: ${standard.map(p => p.name).join(', ')} | Free: ${free.map(p => p.name).join(', ')}`, { freePlans });
    },
  },
  {
    category: 'Security Baseline',
    check: 'Storage account security settings',
    run: async (token, subId) => {
      const body = await armGet(`https://management.azure.com/subscriptions/${subId}/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01`, token);
      const accounts = body.value || [];
      if (accounts.length === 0) {
        return result('Security Baseline', 'Storage account security settings', 'Manual / Process', 'No storage accounts found');
      }
      const issues = [];
      const flagged = [];
      for (const sa of accounts) {
        const p = sa.properties || {};
        const saIssues = [];
        if (!p.supportsHttpsTrafficOnly) saIssues.push('secure transfer disabled');
        if (p.minimumTlsVersion && p.minimumTlsVersion < 'TLS1_2') saIssues.push('min TLS below 1.2');
        if (p.allowBlobPublicAccess) saIssues.push('public blob access allowed');
        if (saIssues.length > 0) {
          issues.push(...saIssues.map(i => `${sa.name}: ${i}`));
          flagged.push({ id: sa.id, name: sa.name, issues: saIssues });
        }
        if (p.publicNetworkAccess === 'Enabled' && p.networkAcls?.defaultAction === 'Allow') issues.push(`${sa.name}: public network access with default Allow`);
      }
      if (issues.length === 0) {
        return result('Security Baseline', 'Storage account security settings', 'Implemented', `${accounts.length} storage account(s) checked - all secure`);
      }
      return result('Security Baseline', 'Storage account security settings', 'Partial', issues.join('; '), { flagged });
    },
  },
  {
    category: 'Security Baseline',
    check: 'Key Vault soft delete & purge protection',
    run: async (token, subId) => {
      const body = await armGet(`https://management.azure.com/subscriptions/${subId}/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01`, token);
      const vaults = body.value || [];
      if (vaults.length === 0) {
        return result('Security Baseline', 'Key Vault soft delete & purge protection', 'Manual / Process', 'No key vaults found');
      }
      const issues = [];
      const flagged = [];
      for (const v of vaults) {
        const p = v.properties || {};
        const vIssues = [];
        if (p.enableSoftDelete === false) vIssues.push('soft delete disabled');
        if (p.enablePurgeProtection !== true) vIssues.push('purge protection disabled');
        if (vIssues.length > 0) {
          issues.push(...vIssues.map(i => `${v.name}: ${i}`));
          flagged.push({ id: v.id, name: v.name, issues: vIssues });
        }
      }
      if (issues.length === 0) {
        return result('Security Baseline', 'Key Vault soft delete & purge protection', 'Implemented', `${vaults.length} key vault(s) checked - all compliant`);
      }
      return result('Security Baseline', 'Key Vault soft delete & purge protection', 'Partial', issues.join('; '), { flagged });
    },
  },
  {
    category: 'Network Topology',
    check: 'NSGs applied to all subnets',
    run: async (token, subId) => {
      const body = await armGet(`https://management.azure.com/subscriptions/${subId}/providers/Microsoft.Network/virtualNetworks?api-version=2023-09-01`, token);
      const vnets = body.value || [];
      if (vnets.length === 0) {
        return result('Network Topology', 'NSGs applied to all subnets', 'Manual / Process', 'No virtual networks found');
      }
      const special = ['GatewaySubnet', 'AzureFirewallSubnet', 'AzureBastionSubnet'];
      const unprotected = [];
      for (const vnet of vnets) {
        for (const subnet of (vnet.properties?.subnets || [])) {
          if (!subnet.properties?.networkSecurityGroup && !special.includes(subnet.name)) {
            unprotected.push(`${vnet.name}/${subnet.name}`);
          }
        }
      }
      if (unprotected.length === 0) {
        return result('Network Topology', 'NSGs applied to all subnets', 'Implemented', `All applicable subnets across ${vnets.length} VNet(s) have an NSG`);
      }
      return result('Network Topology', 'NSGs applied to all subnets', 'Partial', `Subnets without NSG: ${unprotected.join(', ')}`);
    },
  },
  {
    category: 'Cost Management',
    check: 'Budgets configured',
    run: async (token, subId) => {
      const body = await armGet(`https://management.azure.com/subscriptions/${subId}/providers/Microsoft.Consumption/budgets?api-version=2023-05-01`, token);
      const budgets = body.value || [];
      if (budgets.length > 0) {
        return result('Cost Management', 'Budgets configured', 'Implemented', `Budget(s): ${budgets.map(b => b.name).join(', ')}`);
      }
      return result('Cost Management', 'Budgets configured', 'Not Implemented', 'No budgets configured at subscription scope');
    },
  },
  {
    category: 'Subscription & Hierarchy',
    check: 'Management Group placement',
    run: async (token, subId) => {
      const body = await armPost('https://management.azure.com/providers/Microsoft.Management/getEntities?api-version=2023-04-01', token, {});
      const entity = (body.value || []).find(e => e.type === '/subscriptions' && e.name === subId);
      const chain = entity?.properties?.parentDisplayNameChain || [];
      if (chain.length > 1) {
        return result('Subscription & Hierarchy', 'Management Group placement', 'Implemented', `MG chain: ${chain.join(' -> ')}`);
      }
      return result('Subscription & Hierarchy', 'Management Group placement', 'Not Implemented', 'Subscription sits directly under the tenant root management group (not in a custom management group)');
    },
  },
  {
    category: 'Network Topology',
    check: 'DDoS Protection on VNets',
    run: async (token, subId) => {
      const body = await armGet(`https://management.azure.com/subscriptions/${subId}/providers/Microsoft.Network/virtualNetworks?api-version=2023-09-01`, token);
      const vnets = body.value || [];
      if (vnets.length === 0) {
        return result('Network Topology', 'DDoS Protection on VNets', 'Manual / Process', 'No virtual networks found');
      }
      const protectedVnets = vnets.filter(v => v.properties?.enableDdosProtection);
      if (protectedVnets.length === vnets.length) {
        return result('Network Topology', 'DDoS Protection on VNets', 'Implemented', `All ${vnets.length} VNet(s) have DDoS Protection enabled`);
      } else if (protectedVnets.length > 0) {
        return result('Network Topology', 'DDoS Protection on VNets', 'Partial', `${protectedVnets.length} of ${vnets.length} VNet(s) protected`);
      }
      return result('Network Topology', 'DDoS Protection on VNets', 'Not Implemented', 'No VNets have DDoS Protection enabled (review if required for internet-facing workloads)');
    },
  },
  {
    category: 'Network Topology',
    check: 'Private Endpoints for PaaS services',
    run: async (token, subId) => {
      const body = await armGet(`https://management.azure.com/subscriptions/${subId}/providers/Microsoft.Network/privateEndpoints?api-version=2023-09-01`, token);
      const pes = body.value || [];
      if (pes.length > 0) {
        return result('Network Topology', 'Private Endpoints for PaaS services', 'Implemented', `${pes.length} private endpoint(s) found`);
      }
      return result('Network Topology', 'Private Endpoints for PaaS services', 'Not Implemented', 'No private endpoints found - PaaS services may be using public endpoints');
    },
  },
  {
    category: 'Monitoring & Logging',
    check: 'Activity Log exported to Log Analytics',
    run: async (token, subId) => {
      const body = await armGet(`https://management.azure.com/subscriptions/${subId}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview`, token);
      const settings = body.value || [];
      if (settings.length > 0) {
        return result('Monitoring & Logging', 'Activity Log exported to Log Analytics', 'Implemented', `Diagnostic setting(s): ${settings.map(s => s.name).join(', ')}`);
      }
      return result('Monitoring & Logging', 'Activity Log exported to Log Analytics', 'Not Implemented', 'No subscription-level diagnostic settings configured for Activity Log export');
    },
  },
  {
    category: 'Backup & DR',
    check: 'Recovery Services Vault with backup items',
    run: async (token, subId) => {
      const [vaultBody, vmBody] = await Promise.all([
        armGet(`https://management.azure.com/subscriptions/${subId}/providers/Microsoft.RecoveryServices/vaults?api-version=2023-04-01`, token),
        armGet(`https://management.azure.com/subscriptions/${subId}/providers/Microsoft.Compute/virtualMachines?api-version=2023-09-01`, token),
      ]);
      const vaults = vaultBody.value || [];
      const vms = vmBody.value || [];

      const protectedIds = new Set();
      let totalItems = 0;
      for (const v of vaults) {
        const filter = encodeURIComponent("backupManagementType eq 'AzureIaasVM'");
        const itemsBody = await armGet(`https://management.azure.com${v.id}/backupProtectedItems?api-version=2023-04-01&$filter=${filter}`, token);
        for (const item of itemsBody.value || []) {
          const srcId = item.properties?.sourceResourceId || item.properties?.virtualMachineId;
          if (srcId) protectedIds.add(srcId.toLowerCase());
          totalItems++;
        }
      }

      const vaultSummaries = vaults.map(v => ({ id: v.id, name: v.name, location: v.location, resourceGroup: v.id.split('/')[4] }));
      const unprotectedVms = vms
        .filter(vm => !protectedIds.has(vm.id.toLowerCase()))
        .map(vm => ({ id: vm.id, name: vm.name, resourceGroup: vm.id.split('/')[4], location: vm.location }));

      if (vaults.length === 0) {
        return result('Backup & DR', 'Recovery Services Vault with backup items', 'Not Implemented', 'No Recovery Services Vaults found in subscription', { vaults: vaultSummaries, vms: unprotectedVms });
      }
      if (totalItems > 0 && unprotectedVms.length === 0) {
        return result('Backup & DR', 'Recovery Services Vault with backup items', 'Implemented', `${vaults.length} vault(s), ${totalItems} protected VM(s)`);
      }
      return result('Backup & DR', 'Recovery Services Vault with backup items', 'Partial', `${vaults.length} vault(s) exist; ${totalItems} protected VM(s), ${unprotectedVms.length} VM(s) without backup`, { vaults: vaultSummaries, vms: unprotectedVms });
    },
  },
  {
    category: 'Cost Management',
    check: 'VM auto-shutdown schedules',
    run: async (token, subId) => {
      const vmBody = await armGet(`https://management.azure.com/subscriptions/${subId}/providers/Microsoft.Compute/virtualMachines?api-version=2023-09-01`, token);
      const vms = vmBody.value || [];
      if (vms.length === 0) {
        return result('Cost Management', 'VM auto-shutdown schedules', 'Manual / Process', 'No VMs found in subscription');
      }
      const filter = encodeURIComponent("resourceType eq 'Microsoft.DevTestLab/schedules'");
      const schedBody = await armGet(`https://management.azure.com/subscriptions/${subId}/resources?api-version=2021-04-01&$filter=${filter}`, token);
      const schedules = schedBody.value || [];
      const scheduledVmNames = new Set(
        schedules
          .map(s => /^shutdown-computevm-(.+)$/i.exec(s.name)?.[1]?.toLowerCase())
          .filter(Boolean)
      );
      const unscheduledVms = vms
        .filter(vm => !scheduledVmNames.has((vm.name || '').toLowerCase()))
        .map(vm => ({ id: vm.id, name: vm.name, resourceGroup: vm.id.split('/')[4], location: vm.location }));
      if (schedules.length > 0 && unscheduledVms.length === 0) {
        return result('Cost Management', 'VM auto-shutdown schedules', 'Implemented', `${schedules.length} auto-shutdown schedule(s) found for ${vms.length} VM(s)`);
      }
      if (unscheduledVms.length < vms.length) {
        return result('Cost Management', 'VM auto-shutdown schedules', 'Partial', `${schedules.length} of ${vms.length} VM(s) have an auto-shutdown schedule`, { vms: unscheduledVms });
      }
      return result('Cost Management', 'VM auto-shutdown schedules', 'Not Implemented', `No auto-shutdown schedules found for ${vms.length} VM(s) - review for non-prod cost savings`, { vms: unscheduledVms });
    },
  },
  {
    category: 'Resource Consistency',
    check: 'Naming convention compliance',
    run: async (token, subId, options) => {
      const rgPrefix = (options?.namingConfig?.rgPrefix || 'rg-').toLowerCase();
      const abbrevByType = {};
      const configuredTypes = options?.namingConfig?.types;
      const sourceTypes = (configuredTypes && Object.keys(configuredTypes).length > 0) ? configuredTypes : {
        'microsoft.storage/storageaccounts': 'st',
        'microsoft.keyvault/vaults': 'kv',
        'microsoft.network/virtualnetworks': 'vnet',
        'microsoft.network/networksecuritygroups': 'nsg',
        'microsoft.compute/virtualmachines': 'vm',
        'microsoft.network/publicipaddresses': 'pip',
        'microsoft.web/sites': 'app',
        'microsoft.sql/servers': 'sql',
      };
      for (const [type, abbrev] of Object.entries(sourceTypes)) {
        if (type && abbrev) abbrevByType[type.toLowerCase()] = abbrev.toLowerCase();
      }

      const [rgsBody, resourcesBody] = await Promise.all([
        armGet(`https://management.azure.com/subscriptions/${subId}/resourcegroups?api-version=2021-04-01`, token),
        armGet(`https://management.azure.com/subscriptions/${subId}/resources?api-version=2021-04-01`, token),
      ]);
      const rgs = rgsBody.value || [];
      const resources = resourcesBody.value || [];
      let checked = 0;
      const nonCompliant = [];
      for (const rg of rgs) {
        checked++;
        if (!rg.name.toLowerCase().startsWith(rgPrefix)) nonCompliant.push(`${rg.name} (expected prefix '${rgPrefix}')`);
      }
      for (const [type, abbrev] of Object.entries(abbrevByType)) {
        for (const item of resources.filter(r => (r.type || '').toLowerCase() === type)) {
          checked++;
          if (!item.name.toLowerCase().startsWith(abbrev)) nonCompliant.push(`${item.name} [${item.type}] (expected prefix '${abbrev}-' or '${abbrev}')`);
        }
      }
      if (checked === 0) {
        return result('Resource Consistency', 'Naming convention compliance', 'Manual / Process', 'No resource groups or resources of checked types found');
      }
      const pct = Math.round(((checked - nonCompliant.length) / checked) * 1000) / 10;
      if (nonCompliant.length === 0) {
        return result('Resource Consistency', 'Naming convention compliance', 'Implemented', `All ${checked} resource(s)/RG(s) checked follow the configured naming convention`);
      } else if (nonCompliant.length < checked) {
        return result('Resource Consistency', 'Naming convention compliance', 'Partial', `${pct}% compliant (${checked} checked). Non-compliant: ${nonCompliant.join('; ')}`);
      }
      return result('Resource Consistency', 'Naming convention compliance', 'Not Implemented', `0 of ${checked} resource(s)/RG(s) follow the configured naming convention`);
    },
  },
  {
    category: 'Resource Consistency',
    check: 'Allowed locations / SKU restriction policy',
    run: async (token, subId) => {
      const allowedLocationsId = 'e56962a6-4747-49cd-b67b-bf8b01975c4c';
      const allowedSkusId = 'cccc23c7-8427-4f53-ad12-b6a63eb452b3';
      const body = await armGet(`https://management.azure.com/subscriptions/${subId}/providers/Microsoft.Authorization/policyAssignments?api-version=2022-06-01`, token);
      const assignments = body.value || [];
      const hasLocations = assignments.some(a => (a.properties?.policyDefinitionId || '').includes(allowedLocationsId));
      const hasSkus = assignments.some(a => (a.properties?.policyDefinitionId || '').includes(allowedSkusId));
      if (hasLocations && hasSkus) {
        return result('Resource Consistency', 'Allowed locations / SKU restriction policy', 'Implemented', "Both 'Allowed locations' and 'Allowed virtual machine SKUs' policies are assigned");
      } else if (hasLocations || hasSkus) {
        const missing = !hasLocations ? ['locations'] : ['skus'];
        const missingLabel = !hasLocations ? 'Allowed locations' : 'Allowed virtual machine SKUs';
        return result('Resource Consistency', 'Allowed locations / SKU restriction policy', 'Partial', `Missing: ${missingLabel} policy assignment`, { missing });
      }
      return result('Resource Consistency', 'Allowed locations / SKU restriction policy', 'Not Implemented', "Neither 'Allowed locations' nor 'Allowed virtual machine SKUs' policies are assigned at subscription scope", { missing: ['locations', 'skus'] });
    },
  },
  {
    category: 'Resource Consistency',
    check: 'Policy compliance state',
    run: async (token, subId) => {
      const body = await armPost(`https://management.azure.com/subscriptions/${subId}/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01`, token, {});
      const summary = (body.value || [])[0];
      const details = summary?.results?.resourceDetails;
      if (!summary || !details) {
        return result('Resource Consistency', 'Policy compliance state', 'Manual / Process', 'No policy compliance data available yet (may take time after policy assignment)');
      }
      const sumBy = state => details.filter(d => d.complianceState === state).reduce((s, d) => s + (d.count || 0), 0);
      const compliant = sumBy('compliant');
      const noncompliant = sumBy('noncompliant');
      const total = compliant + noncompliant;
      if (total === 0) {
        return result('Resource Consistency', 'Policy compliance state', 'Manual / Process', 'No evaluated resources found in policy compliance state');
      }
      const pct = Math.round((compliant / total) * 1000) / 10;
      if (pct === 100) {
        return result('Resource Consistency', 'Policy compliance state', 'Implemented', `100% policy compliant (${compliant} of ${total} resources)`);
      } else if (pct >= 50) {
        return result('Resource Consistency', 'Policy compliance state', 'Partial', `${pct}% policy compliant (${compliant} of ${total} resources)`);
      }
      return result('Resource Consistency', 'Policy compliance state', 'Not Implemented', `${pct}% policy compliant (${compliant} of ${total} resources)`);
    },
  },
  {
    category: 'Cost Management',
    check: 'Reserved Instance / Savings Plan coverage',
    run: async (token, subId) => {
      const r = await fetch('https://management.azure.com/providers/Microsoft.Capacity/reservationOrders?api-version=2022-11-01', {
        headers: { Authorization: `Bearer ${token}`, 'Accept-Language': 'en-US' },
      });
      if (r.status === 403) {
        return result('Cost Management', 'Reserved Instance / Savings Plan coverage', 'Manual / Process', 'Caller does not have Reservations Reader access at billing scope - review manually in Cost Management > Reservations');
      }
      const body = await r.json().catch(() => ({}));
      if (!r.ok) {
        return result('Cost Management', 'Reserved Instance / Savings Plan coverage', 'Error', body.error?.message || `ARM call failed (${r.status})`);
      }
      const orders = body.value || [];
      if (orders.length > 0) {
        return result('Cost Management', 'Reserved Instance / Savings Plan coverage', 'Implemented', `${orders.length} reservation order(s) found at tenant scope - verify coverage applies to this subscription's workloads`);
      }
      return result('Cost Management', 'Reserved Instance / Savings Plan coverage', 'Not Implemented', 'No Reserved Instances or Savings Plans found - review steady-state usage for cost savings opportunities');
    },
  },
  {
    category: 'Security Baseline',
    check: 'Regulatory compliance (Defender for Cloud)',
    run: async (token, subId) => {
      const body = await armGet(`https://management.azure.com/subscriptions/${subId}/providers/Microsoft.Security/regulatoryComplianceStandards?api-version=2019-01-01-preview`, token);
      const standards = body.value || [];
      if (standards.length === 0) {
        return result('Security Baseline', 'Regulatory compliance (Defender for Cloud)', 'Not Implemented', 'No regulatory compliance standards assigned in Defender for Cloud');
      }
      const passed = standards.reduce((s, x) => s + (x.properties?.passedControls || 0), 0);
      const failed = standards.reduce((s, x) => s + (x.properties?.failedControls || 0), 0);
      const names = standards.map(s => s.name).join(', ');
      const total = passed + failed;
      if (total === 0) {
        return result('Security Baseline', 'Regulatory compliance (Defender for Cloud)', 'Manual / Process', `Standards assigned (${names}) but no control results available yet`);
      }
      const pct = Math.round((passed / total) * 1000) / 10;
      if (pct === 100) {
        return result('Security Baseline', 'Regulatory compliance (Defender for Cloud)', 'Implemented', `${pct}% controls passed across: ${names}`);
      } else if (pct >= 50) {
        return result('Security Baseline', 'Regulatory compliance (Defender for Cloud)', 'Partial', `${pct}% controls passed (${passed} of ${total}) across: ${names}`);
      }
      return result('Security Baseline', 'Regulatory compliance (Defender for Cloud)', 'Not Implemented', `${pct}% controls passed (${passed} of ${total}) across: ${names}`);
    },
  },
  {
    category: 'Scoring',
    check: 'Microsoft Defender Secure Score',
    run: async (token, subId) => {
      const body = await armGet(`https://management.azure.com/subscriptions/${subId}/providers/Microsoft.Security/secureScores?api-version=2020-01-01-preview`, token);
      const ascScore = (body.value || []).find(v => v.name === 'ascScore');
      if (ascScore && ascScore.properties?.score?.max > 0) {
        const pct = Math.round((ascScore.properties.score.current / ascScore.properties.score.max) * 1000) / 10;
        return result('Scoring', 'Microsoft Defender Secure Score', 'Manual / Process', `${pct}% (${ascScore.properties.score.current} of ${ascScore.properties.score.max} points) - see Defender for Cloud for detail`);
      }
      return result('Scoring', 'Microsoft Defender Secure Score', 'Manual / Process', 'No secure score data returned - Defender for Cloud may not be enabled');
    },
  },
];

// ───────────────────────────────────────────
// Scoring
// ───────────────────────────────────────────
const SCORE_WEIGHTS = { Implemented: 1, Partial: 0.5, 'Not Implemented': 0 };

function computeScoring(results) {
  const scorable = results.filter(r => r.status in SCORE_WEIGHTS);
  const excluded = results.length - scorable.length;
  const earned = scorable.reduce((sum, r) => sum + SCORE_WEIGHTS[r.status], 0);
  const max = scorable.length;
  const overallPct = max > 0 ? Math.round((earned / max) * 1000) / 10 : 0;

  let maturity = 'Initial';
  if (overallPct >= 90) maturity = 'Optimized';
  else if (overallPct >= 75) maturity = 'Defined';
  else if (overallPct >= 50) maturity = 'Developing';

  const byCategory = {};
  for (const r of scorable) {
    if (!byCategory[r.category]) byCategory[r.category] = { earned: 0, max: 0 };
    byCategory[r.category].earned += SCORE_WEIGHTS[r.status];
    byCategory[r.category].max += 1;
  }
  const categoryScores = Object.entries(byCategory).map(([category, v]) => ({
    category,
    earned: v.earned,
    max: v.max,
    percent: Math.round((v.earned / v.max) * 1000) / 10,
  }));

  return { overallPct, maturity, earned, max, excluded, categoryScores };
}

// ───────────────────────────────────────────
// API routes
// ───────────────────────────────────────────
app.get('/api/subscriptions', async (req, res) => {
  try {
    const token = getAzToken();
    const body = await armGet('https://management.azure.com/subscriptions?api-version=2020-01-01', token);
    const subs = (body.value || []).map(s => ({ id: s.subscriptionId, name: s.displayName, state: s.state }));
    res.json({ subscriptions: subs });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

async function runChecksForSubscription(token, subscriptionId, namingConfig) {
  const results = await Promise.all(CHECKS.map(async c => {
    try {
      return await c.run(token, subscriptionId, { namingConfig });
    } catch (e) {
      return result(c.category, c.check, 'Error', e.message);
    }
  }));
  const scoring = computeScoring(results);
  return { results, scoring };
}

app.post('/api/assess', async (req, res) => {
  try {
    const { subscriptionId, namingConfig } = req.body;
    if (!subscriptionId) return res.status(400).json({ error: 'subscriptionId is required' });
    const token = getAzToken();

    const { results, scoring } = await runChecksForSubscription(token, subscriptionId, namingConfig);
    res.json({ subscriptionId, results, scoring });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/tags/apply', async (req, res) => {
  try {
    const { resourceIds, tags } = req.body;
    if (!Array.isArray(resourceIds) || resourceIds.length === 0) return res.status(400).json({ error: 'resourceIds is required' });
    if (!tags || typeof tags !== 'object' || Object.keys(tags).length === 0) return res.status(400).json({ error: 'tags is required' });
    const token = getAzToken();

    const outcomes = [];
    for (const id of resourceIds) {
      try {
        const url = `https://management.azure.com${id}/providers/Microsoft.Resources/tags/default?api-version=2021-04-01`;
        await armPatch(url, token, { properties: { tags }, operation: 'Merge' });
        outcomes.push({ id, status: 'success' });
      } catch (e) {
        outcomes.push({ id, status: 'error', message: e.message });
      }
    }
    res.json({ outcomes });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Add CanNotDelete locks to selected resource groups
app.post('/api/locks/apply', async (req, res) => {
  try {
    const { subscriptionId, resourceGroups } = req.body;
    if (!subscriptionId) return res.status(400).json({ error: 'subscriptionId is required' });
    if (!Array.isArray(resourceGroups) || resourceGroups.length === 0) return res.status(400).json({ error: 'resourceGroups is required' });
    const token = getAzToken();

    const outcomes = [];
    for (const rg of resourceGroups) {
      try {
        const url = `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${rg}/providers/Microsoft.Authorization/locks/caf-cannotdelete?api-version=2020-05-01`;
        await armPut(url, token, { properties: { level: 'CanNotDelete', notes: 'Added by CAF Assessment tool' } });
        outcomes.push({ resourceGroup: rg, status: 'success' });
      } catch (e) {
        outcomes.push({ resourceGroup: rg, status: 'error', message: e.message });
      }
    }
    res.json({ outcomes });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Upgrade selected Defender for Cloud plans to Standard tier
app.post('/api/defender/upgrade', async (req, res) => {
  try {
    const { subscriptionId, plans } = req.body;
    if (!subscriptionId) return res.status(400).json({ error: 'subscriptionId is required' });
    if (!Array.isArray(plans) || plans.length === 0) return res.status(400).json({ error: 'plans is required' });
    const token = getAzToken();

    const outcomes = [];
    for (const plan of plans) {
      try {
        const url = `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Security/pricings/${plan}?api-version=2024-01-01`;
        await armPut(url, token, { properties: { pricingTier: 'Standard' } });
        outcomes.push({ plan, status: 'success' });
      } catch (e) {
        outcomes.push({ plan, status: 'error', message: e.message });
      }
    }
    res.json({ outcomes });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Fix common storage account security settings (HTTPS-only, min TLS 1.2, disable public blob access)
app.post('/api/storage/fix', async (req, res) => {
  try {
    const { resourceIds } = req.body;
    if (!Array.isArray(resourceIds) || resourceIds.length === 0) return res.status(400).json({ error: 'resourceIds is required' });
    const token = getAzToken();

    const outcomes = [];
    for (const id of resourceIds) {
      try {
        const url = `https://management.azure.com${id}?api-version=2023-01-01`;
        await armPatch(url, token, {
          properties: {
            supportsHttpsTrafficOnly: true,
            minimumTlsVersion: 'TLS1_2',
            allowBlobPublicAccess: false,
          },
        });
        outcomes.push({ id, status: 'success' });
      } catch (e) {
        outcomes.push({ id, status: 'error', message: e.message });
      }
    }
    res.json({ outcomes });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Enable Key Vault soft delete and purge protection (purge protection cannot be undone)
app.post('/api/keyvault/fix', async (req, res) => {
  try {
    const { resourceIds } = req.body;
    if (!Array.isArray(resourceIds) || resourceIds.length === 0) return res.status(400).json({ error: 'resourceIds is required' });
    const token = getAzToken();

    const outcomes = [];
    for (const id of resourceIds) {
      try {
        const url = `https://management.azure.com${id}?api-version=2023-07-01`;
        await armPatch(url, token, {
          properties: {
            enableSoftDelete: true,
            enablePurgeProtection: true,
          },
        });
        outcomes.push({ id, status: 'success' });
      } catch (e) {
        outcomes.push({ id, status: 'error', message: e.message });
      }
    }
    res.json({ outcomes });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Create a monthly subscription budget with an alert threshold
app.post('/api/budget/create', async (req, res) => {
  try {
    const { subscriptionId, name, amount, thresholdPercent, contactEmail } = req.body;
    if (!subscriptionId) return res.status(400).json({ error: 'subscriptionId is required' });
    if (!name) return res.status(400).json({ error: 'name is required' });
    if (!amount || isNaN(Number(amount))) return res.status(400).json({ error: 'amount must be a number' });
    if (!contactEmail) return res.status(400).json({ error: 'contactEmail is required' });
    const token = getAzToken();

    const now = new Date();
    const startDate = new Date(now.getFullYear(), now.getMonth(), 1);
    const endDate = new Date(now.getFullYear() + 5, now.getMonth(), 1);
    const fmt = d => d.toISOString().slice(0, 10) + 'T00:00:00Z';

    const url = `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Consumption/budgets/${encodeURIComponent(name)}?api-version=2023-05-01`;
    await armPut(url, token, {
      properties: {
        category: 'Cost',
        amount: Number(amount),
        timeGrain: 'Monthly',
        timePeriod: { startDate: fmt(startDate), endDate: fmt(endDate) },
        notifications: {
          Alert1: {
            enabled: true,
            operator: 'GreaterThan',
            threshold: thresholdPercent ? Number(thresholdPercent) : 80,
            contactEmails: [contactEmail],
            thresholdType: 'Actual',
          },
        },
      },
    });
    res.json({ status: 'success' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/vm/autoshutdown', async (req, res) => {
  try {
    const { subscriptionId, vms, time, timeZoneId, notificationEmail } = req.body;
    if (!subscriptionId) return res.status(400).json({ error: 'subscriptionId is required' });
    if (!Array.isArray(vms) || vms.length === 0) return res.status(400).json({ error: 'vms is required' });
    if (!/^\d{4}$/.test(time || '')) return res.status(400).json({ error: 'time must be in HHmm format, e.g. 1900' });
    if (!timeZoneId) return res.status(400).json({ error: 'timeZoneId is required' });
    const token = getAzToken();

    const outcomes = [];
    for (const vm of vms) {
      try {
        const scheduleName = `shutdown-computevm-${vm.name.toLowerCase()}`;
        const url = `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${vm.resourceGroup}/providers/Microsoft.DevTestLab/schedules/${scheduleName}?api-version=2018-09-15`;
        await armPut(url, token, {
          location: vm.location,
          properties: {
            status: 'Enabled',
            taskType: 'ComputeVmShutdownTask',
            dailyRecurrence: { time },
            timeZoneId,
            targetResourceId: vm.id,
            notificationSettings: notificationEmail
              ? { status: 'Enabled', timeInMinutes: 30, emailRecipient: notificationEmail, notificationLocale: 'en' }
              : { status: 'Disabled', timeInMinutes: 30 },
          },
        });
        outcomes.push({ id: vm.id, name: vm.name, status: 'success' });
      } catch (e) {
        outcomes.push({ id: vm.id, name: vm.name, status: 'error', message: e.message });
      }
    }
    res.json({ outcomes });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/policy/restrictions', async (req, res) => {
  try {
    const { subscriptionId, locations, skus } = req.body;
    if (!subscriptionId) return res.status(400).json({ error: 'subscriptionId is required' });
    const token = getAzToken();

    const outcomes = [];
    if (Array.isArray(locations) && locations.length > 0) {
      try {
        const policyDefId = 'e56962a6-4747-49cd-b67b-bf8b01975c4c';
        const url = `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Authorization/policyAssignments/allowed-locations?api-version=2022-06-01`;
        await armPut(url, token, {
          properties: {
            displayName: 'Allowed locations',
            policyDefinitionId: `/providers/Microsoft.Authorization/policyDefinitions/${policyDefId}`,
            parameters: { listOfAllowedLocations: { value: locations } },
          },
        });
        outcomes.push({ policy: 'Allowed locations', status: 'success' });
      } catch (e) {
        outcomes.push({ policy: 'Allowed locations', status: 'error', message: e.message });
      }
    }
    if (Array.isArray(skus) && skus.length > 0) {
      try {
        const policyDefId = 'cccc23c7-8427-4f53-ad12-b6a63eb452b3';
        const url = `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Authorization/policyAssignments/allowed-vm-skus?api-version=2022-06-01`;
        await armPut(url, token, {
          properties: {
            displayName: 'Allowed virtual machine SKUs',
            policyDefinitionId: `/providers/Microsoft.Authorization/policyDefinitions/${policyDefId}`,
            parameters: { listOfAllowedSKUs: { value: skus } },
          },
        });
        outcomes.push({ policy: 'Allowed virtual machine SKUs', status: 'success' });
      } catch (e) {
        outcomes.push({ policy: 'Allowed virtual machine SKUs', status: 'error', message: e.message });
      }
    }
    if (outcomes.length === 0) return res.status(400).json({ error: 'Provide at least one of locations or skus' });
    res.json({ outcomes });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/loganalytics/workspaces', async (req, res) => {
  try {
    const { subscriptionId } = req.query;
    if (!subscriptionId) return res.status(400).json({ error: 'subscriptionId is required' });
    const token = getAzToken();
    const body = await armGet(`https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.OperationalInsights/workspaces?api-version=2022-10-01`, token);
    const workspaces = (body.value || []).map(w => ({ id: w.id, name: w.name, location: w.location, resourceGroup: w.id.split('/')[4] }));
    res.json({ workspaces });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/monitoring/activitylog', async (req, res) => {
  try {
    const { subscriptionId, workspaceId, name } = req.body;
    if (!subscriptionId) return res.status(400).json({ error: 'subscriptionId is required' });
    if (!workspaceId) return res.status(400).json({ error: 'workspaceId is required' });
    const token = getAzToken();

    const categories = ['Administrative', 'Security', 'ServiceHealth', 'Alert', 'Recommendation', 'Policy', 'Autoscale', 'ResourceHealth'];
    const settingName = name || 'activity-log-to-law';
    const url = `https://management.azure.com/subscriptions/${subscriptionId}/providers/microsoft.insights/diagnosticSettings/${encodeURIComponent(settingName)}?api-version=2021-05-01-preview`;
    await armPut(url, token, {
      properties: {
        workspaceId,
        logs: categories.map(category => ({ category, enabled: true })),
      },
    });
    res.json({ status: 'success' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/managementgroups', async (req, res) => {
  try {
    const token = getAzToken();
    const body = await armGet('https://management.azure.com/providers/Microsoft.Management/managementGroups?api-version=2023-04-01', token);
    const groups = (body.value || []).map(g => ({ id: g.id, name: g.name, displayName: g.properties?.displayName || g.name }));
    res.json({ groups });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/subscription/move-mg', async (req, res) => {
  try {
    const { subscriptionId, managementGroupId } = req.body;
    if (!subscriptionId) return res.status(400).json({ error: 'subscriptionId is required' });
    if (!managementGroupId) return res.status(400).json({ error: 'managementGroupId is required' });
    const token = getAzToken();
    const url = `https://management.azure.com/providers/Microsoft.Management/managementGroups/${managementGroupId}/subscriptions/${subscriptionId}?api-version=2023-04-01`;
    await armPut(url, token, {});
    res.json({ status: 'success' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

async function waitForVaultReady(url, token, attempts = 6, delayMs = 5000) {
  for (let i = 0; i < attempts; i++) {
    const body = await armGet(url, token);
    if (body.properties?.provisioningState === 'Succeeded') return;
    await new Promise(r => setTimeout(r, delayMs));
  }
}

app.post('/api/backup/configure', async (req, res) => {
  try {
    const { subscriptionId, vms, vaults } = req.body;
    if (!subscriptionId) return res.status(400).json({ error: 'subscriptionId is required' });
    if (!Array.isArray(vms) || vms.length === 0) return res.status(400).json({ error: 'vms is required' });
    const token = getAzToken();

    const vaultByLocation = {};
    for (const v of (Array.isArray(vaults) ? vaults : [])) {
      if (!vaultByLocation[v.location]) vaultByLocation[v.location] = v.id;
    }

    const outcomes = [];
    for (const vm of vms) {
      try {
        let vaultId = vaultByLocation[vm.location];
        if (!vaultId) {
          const vaultName = `rsv-${vm.location}`;
          vaultId = `/subscriptions/${subscriptionId}/resourceGroups/${vm.resourceGroup}/providers/Microsoft.RecoveryServices/vaults/${vaultName}`;
          const url = `https://management.azure.com${vaultId}?api-version=2023-04-01`;
          await armPut(url, token, { location: vm.location, sku: { name: 'RS0', tier: 'Standard' }, properties: {} });
          await waitForVaultReady(url, token);
          vaultByLocation[vm.location] = vaultId;
        }

        const policyId = `${vaultId}/backupPolicies/DefaultPolicy`;
        const containerName = `iaasvmcontainer;iaasvmcontainerv2;${vm.resourceGroup};${vm.name}`;
        const itemName = `vm;iaasvmcontainerv2;${vm.resourceGroup};${vm.name}`;
        const url = `https://management.azure.com${vaultId}/backupFabrics/Azure/protectionContainers/${containerName}/protectedItems/${itemName}?api-version=2023-04-01`;
        await armPut(url, token, {
          properties: {
            protectedItemType: 'Microsoft.Compute/virtualMachines',
            policyId,
            sourceResourceId: vm.id,
          },
        });
        outcomes.push({ id: vm.id, name: vm.name, status: 'success', vaultId });
      } catch (e) {
        outcomes.push({ id: vm.id, name: vm.name, status: 'error', message: e.message });
      }
    }
    res.json({ outcomes });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => {
  console.log(`CAF Webapp backend running at http://localhost:${PORT}`);
});
