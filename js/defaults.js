/*
 * Default MIRE dataset: attack steps grouped by MITRE ATT&CK tactic, common security tooling / OS features,
 * a baseline defense layer and two example budget projects to compare.
 * Values are illustrative starting points — review them against your own CTI and environment.
 */
(function (root, factory) {
  const D = factory();
  if (typeof module === 'object' && module.exports) module.exports = D;
  else root.MIRE_DEFAULTS = D;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const TACTICS = [
    'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence',
    'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
    'Collection', 'Command and Control', 'Exfiltration', 'Impact',
  ];

  const ACTORS = ['APT29', 'FIN6', 'FIN12', 'Pentest Oracle'];
  const ZONES = ['Perimeter', 'Endpoint', 'Datacenter', 'Cloud', 'Identity'];

  // key, name, tactic, impact, probability, means, [APT29, FIN6, FIN12, Pentest Oracle],
  // mapped defenses: key uses the defense's typical action, key:level overrides it for this attack
  const ATTACKS = [
    ['recon', 'Active scanning', 'Reconnaissance', 1, 5, 5, [1, 0, 0, 1], 'fw waf ndr vuln'],
    ['infra', 'Acquire infrastructure / domains', 'Resource Development', 1, 4, 4, [1, 1, 1, 1], 'dns proxy'],
    ['phish_att', 'Phishing — attachment', 'Initial Access', 4, 5, 5, [1, 1, 1, 1], 'mailgw awareness asr av edr allowlist'],
    ['phish_link', 'Phishing — link', 'Initial Access', 4, 5, 5, [1, 1, 1, 1], 'mailgw awareness:5 proxy dns mfa'],
    ['usb', 'Removable media (USB)', 'Initial Access', 3, 2, 3, [0, 0, 0, 1], 'usbctl av edr allowlist'],
    ['exploit_pub', 'Exploit public-facing application', 'Initial Access', 5, 4, 3, [1, 1, 0, 1], 'waf patch vuln fw ndr seg'],
    ['valid_ext', 'Valid accounts on external services (VPN, RDP)', 'Initial Access', 5, 4, 4, [1, 1, 1, 1], 'mfa ca fw siem'],
    ['driveby', 'Drive-by compromise', 'Initial Access', 3, 3, 3, [1, 0, 0, 0], 'proxy dns patch edr'],
    ['supply', 'Supply chain compromise', 'Initial Access', 5, 2, 1, [1, 0, 0, 0], 'edr ndr seg siem allowlist'],
    ['script', 'Command & scripting interpreter (PowerShell…)', 'Execution', 4, 5, 5, [1, 1, 1, 1], 'edr asr allowlist sysmon siem'],
    ['userexec', 'User execution of malicious file', 'Execution', 4, 4, 5, [1, 1, 1, 1], 'av edr asr allowlist awareness'],
    ['schtask', 'Scheduled task / WMI execution', 'Execution', 3, 4, 4, [1, 1, 1, 1], 'edr sysmon siem noadmin'],
    ['acct', 'Create or modify accounts', 'Persistence', 4, 3, 4, [1, 1, 1, 1], 'siem adhard pam deception'],
    ['runkey', 'Registry run keys / startup folder', 'Persistence', 3, 4, 5, [1, 1, 1, 1], 'edr av sysmon noadmin'],
    ['webshell', 'Web shell', 'Persistence', 4, 3, 4, [0, 1, 0, 1], 'waf edr siem allowlist'],
    ['privesc', 'Exploitation for privilege escalation', 'Privilege Escalation', 4, 3, 3, [1, 0, 1, 1], 'patch edr vuln'],
    ['uac', 'Abuse elevation control (UAC bypass)', 'Privilege Escalation', 3, 3, 4, [1, 1, 1, 1], 'noadmin edr asr'],
    ['killav', 'Disable or modify security tools', 'Defense Evasion', 4, 4, 4, [1, 1, 1, 1], 'edr siem noadmin'],
    ['lolbin', 'Obfuscation & living-off-the-land binaries', 'Defense Evasion', 3, 5, 4, [1, 1, 1, 1], 'edr sysmon allowlist asr'],
    ['lsass', 'OS credential dumping (LSASS)', 'Credential Access', 5, 4, 4, [1, 1, 1, 1], 'credguard edr:1 asr noadmin pam'],
    ['spray', 'Brute force / password spraying', 'Credential Access', 4, 4, 5, [1, 0, 0, 1], 'mfa ca siem adhard'],
    ['kerberoast', 'Kerberoasting', 'Credential Access', 4, 3, 4, [1, 0, 1, 1], 'adhard pam deception siem'],
    ['discovery', 'AD & network discovery', 'Discovery', 2, 5, 5, [1, 1, 1, 1], 'deception edr ndr seg'],
    ['remote', 'Remote services (RDP, SMB, WinRM)', 'Lateral Movement', 4, 4, 4, [1, 1, 1, 1], 'lfw seg pam laps ndr'],
    ['pth', 'Pass-the-hash / pass-the-ticket', 'Lateral Movement', 5, 3, 3, [1, 1, 1, 1], 'laps credguard pam adhard edr'],
    ['shares', 'Data from network shares & repositories', 'Collection', 3, 4, 4, [1, 1, 1, 1], 'dlp seg siem deception'],
    ['email', 'Email collection', 'Collection', 3, 3, 3, [1, 0, 0, 0], 'ca casb siem'],
    ['c2web', 'C2 over web protocols (HTTPS)', 'Command and Control', 4, 5, 4, [1, 1, 1, 1], 'proxy fw ndr edr dns'],
    ['c2dns', 'DNS tunnelling', 'Command and Control', 3, 2, 3, [0, 1, 0, 1], 'dns ndr fw'],
    ['rmm', 'Remote access software (AnyDesk…)', 'Command and Control', 3, 3, 5, [0, 0, 1, 1], 'allowlist proxy edr fw'],
    ['exfil', 'Exfiltration over C2 / web service', 'Exfiltration', 5, 4, 4, [1, 1, 1, 0], 'proxy dlp ndr casb fw'],
    ['exfilcloud', 'Exfiltration to cloud storage', 'Exfiltration', 5, 3, 4, [1, 0, 1, 0], 'casb dlp proxy'],
    ['ransom', 'Data encrypted for impact (ransomware)', 'Impact', 5, 3, 4, [0, 1, 1, 0], 'backup edr seg:3 av'],
    ['nobackup', 'Inhibit system recovery (delete backups)', 'Impact', 5, 3, 4, [0, 1, 1, 0], 'backup pam siem'],
    ['wiper', 'Data destruction / wiper', 'Impact', 5, 1, 2, [0, 0, 0, 0], 'backup edr seg'],
  ];

  // key, name, category, cost, difficulty, lack of efficiency, typical action (5D level used in the mapping),
  // missing coverage per zone [Perimeter, Endpoint, Datacenter, Cloud, Identity] (1 full … 5 mostly missing, 0 not deployed)
  const DEFENSES = [
    ['fw', 'Perimeter firewall', 'Network', 3, 2, 2, 1, [2, 5, 2, 5, 5]],
    ['lfw', 'Local firewall (host)', 'OS feature', 1, 3, 3, 1, [5, 3, 3, 5, 5]],
    ['proxy', 'Web proxy', 'Network', 3, 3, 2, 1, [2, 3, 5, 5, 5]],
    ['dns', 'DNS filtering', 'Network', 2, 1, 2, 1, [3, 3, 5, 5, 5]],
    ['mailgw', 'Mail gateway (sandbox)', 'Messaging', 3, 2, 2, 1, [2, 5, 5, 2, 5]],
    ['waf', 'Web application firewall', 'Network', 3, 3, 3, 1, [3, 5, 5, 5, 5]],
    ['ndr', 'NDR / IDS', 'Detection', 4, 3, 3, 5, [3, 5, 3, 5, 5]],
    ['seg', 'Network segmentation', 'Network', 4, 4, 2, 2, [5, 3, 3, 5, 5]],
    ['av', 'Antivirus', 'Endpoint', 2, 1, 4, 1, [5, 2, 2, 5, 5]],
    ['edr', 'EDR', 'Endpoint', 4, 3, 1, 4, [5, 5, 5, 5, 5]],
    ['asr', 'Attack surface reduction / macro blocking', 'OS feature', 1, 3, 2, 1, [5, 3, 5, 5, 5]],
    ['allowlist', 'Application allowlisting (WDAC / AppLocker)', 'OS feature', 2, 5, 1, 1, [5, 4, 4, 5, 5]],
    ['usbctl', 'USB device control', 'Endpoint', 2, 2, 1, 1, [5, 2, 5, 5, 5]],
    ['noadmin', 'No local admin rights', 'OS feature', 2, 3, 1, 1, [5, 2, 5, 5, 5]],
    ['credguard', 'Credential Guard / LSA protection', 'OS feature', 1, 3, 2, 1, [5, 3, 3, 5, 5]],
    ['laps', 'LAPS', 'OS feature', 1, 2, 1, 2, [5, 2, 2, 5, 5]],
    ['sysmon', 'Sysmon / advanced audit policy', 'Detection', 1, 3, 3, 5, [5, 3, 3, 5, 5]],
    ['siem', 'SIEM / SOC monitoring', 'Detection', 4, 4, 3, 5, [3, 3, 3, 3, 3]],
    ['deception', 'Honeytokens / deception', 'Detection', 2, 2, 2, 5, [5, 5, 4, 5, 4]],
    ['mfa', 'MFA (VPN, SSO, webmail)', 'Identity', 2, 2, 1, 1, [2, 5, 5, 2, 2]],
    ['ca', 'Conditional access', 'Identity', 3, 3, 2, 1, [5, 5, 5, 5, 5]],
    ['pam', 'PAM / admin tiering', 'Identity', 5, 5, 2, 2, [5, 5, 5, 5, 5]],
    ['adhard', 'AD hardening (AES Kerberos, audits)', 'Identity', 2, 3, 2, 2, [5, 5, 5, 5, 3]],
    ['patch', 'Patch management', 'Process', 3, 3, 2, 1, [3, 3, 3, 3, 5]],
    ['vuln', 'Vulnerability scanning', 'Process', 2, 2, 3, 3, [2, 5, 2, 2, 5]],
    ['dlp', 'Data loss prevention', 'Data', 4, 4, 3, 3, [4, 4, 5, 4, 5]],
    ['casb', 'CASB / SaaS security', 'Cloud', 3, 3, 3, 3, [5, 5, 5, 3, 5]],
    ['backup', 'Offline / immutable backups', 'Resilience', 3, 2, 1, 3, [5, 5, 2, 2, 5]],
    ['awareness', 'Security awareness & phishing simulation', 'People', 2, 2, 4, 3, [5, 2, 5, 5, 5]],
  ];

  // Example projects: missing-coverage overrides on top of the baseline layer.
  const PROJECTS = [
    ['Project X — EDR rollout', { edr: [5, 2, 2, 5, 5] }],
    ['Project Y — Identity (CA + PAM)', { ca: [5, 5, 5, 3, 3], pam: [5, 5, 3, 5, 3] }],
  ];

  function build() {
    const zonesOf = (arr) => Object.fromEntries(ZONES.map((z, i) => [z, arr[i]]));
    const attacks = ATTACKS.map(([key, name, tactic, impact, probability, means, flags]) => ({
      id: 'a_' + key,
      name,
      tactic,
      impact,
      probability,
      means,
      actors: Object.fromEntries(ACTORS.map((x, i) => [x, flags[i]])),
    }));
    const defenses = DEFENSES.map(([key, name, category]) => ({ id: 'd_' + key, name, category }));
    const baseValues = {};
    const action = {};
    for (const [key, , , cost, difficulty, lack, act, z] of DEFENSES) {
      baseValues['d_' + key] = { cost, difficulty, lack, zones: zonesOf(z) };
      action[key] = act;
    }
    const layers = [{ id: 'l_base', name: 'Baseline', values: baseValues }];
    PROJECTS.forEach(([name, overrides], i) => {
      const values = JSON.parse(JSON.stringify(baseValues));
      for (const [key, z] of Object.entries(overrides)) values['d_' + key].zones = zonesOf(z);
      layers.push({ id: 'l_p' + (i + 1), name, values });
    });
    const mapping = {};
    for (const [key, , , , , , , defs] of ATTACKS) {
      mapping['a_' + key] = Object.fromEntries(defs.split(' ').map((d) => {
        const [k, level] = d.split(':');
        return ['d_' + k, Number(level) || action[k]];
      }));
    }
    return {
      version: 2,
      actors: ACTORS.slice(),
      zones: ZONES.slice(),
      attacks,
      defenses,
      layers,
      mapping,
      view: { actors: [], zone: '', layers: ['l_base'], cert: false, compare: layers.map((l) => l.id) },
    };
  }

  return { TACTICS, build };
});
