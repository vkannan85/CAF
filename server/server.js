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
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error?.message || `ARM PATCH failed (${r.status}): ${JSON.stringify(body)}`);
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
      const body = await armGet(`https://management.azure.com/subscriptions/${subId}/providers/Microsoft.Authorization/locks?api-version=2020-05-01`, token);
      const locks = (body.value || []).filter(l => l.properties?.level === 'CanNotDelete');
      if (locks.length > 0) {
        return result('Governance & Tagging', 'Resource locks (CanNotDelete)', 'Implemented', `${locks.length} CanNotDelete lock(s) found`);
      }
      return result('Governance & Tagging', 'Resource locks (CanNotDelete)', 'Not Implemented', 'No CanNotDelete locks found on any scope');
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
      if (standard.length === 0) {
        return result('Security Baseline', 'Defender for Cloud plans (Standard tier)', 'Not Implemented', 'All Defender plans are on Free tier');
      } else if (free.length === 0) {
        return result('Security Baseline', 'Defender for Cloud plans (Standard tier)', 'Implemented', `All Defender plans on Standard: ${standard.map(p => p.name).join(', ')}`);
      }
      return result('Security Baseline', 'Defender for Cloud plans (Standard tier)', 'Partial', `Standard: ${standard.map(p => p.name).join(', ')} | Free: ${free.map(p => p.name).join(', ')}`);
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
      for (const sa of accounts) {
        const p = sa.properties || {};
        if (!p.supportsHttpsTrafficOnly) issues.push(`${sa.name}: secure transfer disabled`);
        if (p.minimumTlsVersion && p.minimumTlsVersion < 'TLS1_2') issues.push(`${sa.name}: min TLS below 1.2`);
        if (p.allowBlobPublicAccess) issues.push(`${sa.name}: public blob access allowed`);
        if (p.publicNetworkAccess === 'Enabled' && p.networkAcls?.defaultAction === 'Allow') issues.push(`${sa.name}: public network access with default Allow`);
      }
      if (issues.length === 0) {
        return result('Security Baseline', 'Storage account security settings', 'Implemented', `${accounts.length} storage account(s) checked - all secure`);
      }
      return result('Security Baseline', 'Storage account security settings', 'Partial', issues.join('; '));
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
      for (const v of vaults) {
        const p = v.properties || {};
        if (p.enableSoftDelete === false) issues.push(`${v.name}: soft delete disabled`);
        if (p.enablePurgeProtection !== true) issues.push(`${v.name}: purge protection disabled`);
      }
      if (issues.length === 0) {
        return result('Security Baseline', 'Key Vault soft delete & purge protection', 'Implemented', `${vaults.length} key vault(s) checked - all compliant`);
      }
      return result('Security Baseline', 'Key Vault soft delete & purge protection', 'Partial', issues.join('; '));
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

app.post('/api/assess', async (req, res) => {
  try {
    const { subscriptionId } = req.body;
    if (!subscriptionId) return res.status(400).json({ error: 'subscriptionId is required' });
    const token = getAzToken();

    const results = await Promise.all(CHECKS.map(async c => {
      try {
        return await c.run(token, subscriptionId);
      } catch (e) {
        return result(c.category, c.check, 'Error', e.message);
      }
    }));

    const scoring = computeScoring(results);
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

app.listen(PORT, () => {
  console.log(`CAF Webapp backend running at http://localhost:${PORT}`);
});
