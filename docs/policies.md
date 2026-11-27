# Policies

The policy engine module: corporate policies on top of a finished audit,
with enforcement for CI. A policy is a YAML file with rules; the engine
checks scan.json and the workspace files against it and writes a
compliance report. The scan is not recomputed: policies read the facts
that are already collected.

Code: `skills/agents-doctor/scripts/policies.py`. Tests:
`tests/test_policies.py`, `tests/test_policy_enforcement.py`.

## Quick start

```
python skills/agents-doctor/scripts/agents_doctor.py audit . --out scan.json
python skills/agents-doctor/scripts/agents_doctor.py policy scan.json \
    --policy corporate.yml --policy team.yml --out report.json
```

`--policy` can be repeated: the files layer (see "Layering").
`--format md` writes a markdown table instead of JSON. The exit codes
are a contract for CI (see "Enforcement v2"): 0 the check passed (or
enforcement is off), 1 a blocking rule fired, 2 a broken or missing
policy file, 3 scan.json cannot be read or has no root, 4 strict
enforcement with rules in status unknown. The report is written
before the exits 0, 1 and 4.

## Policy format

```yaml
version: 2

policy:
  name: corporate-baseline        # metadata, goes into the report
  description: Mandatory rules for all workspaces

  enforcement:                    # v2: see "Enforcement v2"
    enabled: true
    default_action: warn
    unknown_action: warn

  secrets:
    severity: critical            # info | warning | error | critical
    block_on_failure: true        # v2: blocks CI, see enforcement
    block_above: high             # v2: severity threshold for blocking

  mcp:
    allowlist:                    # names of allowed MCP servers
      - approved-server

  instructions:
    require_agents_md: true

  git:
    prevent_secret_commits: true

  permissions:
    forbid_wildcard: true         # Bash(*), danger-full-access and similar

  content:
    ban_patterns:                 # regex (re.search) over text files
      - 'INTERNAL-PROJECT-CODE'
      - 'ACME-CONFIDENTIAL'

  harness_versions:
    required:                     # harness id -> version range
      claude_code: '>=2.1'
      codex: '<2'

  required_skills:                # names of required skills
    - notes

custom_rules:                     # extensibility: arbitrary rules
  - id: POL-CUSTOM-001
    check: content.regex
    patterns: ['internal-codename']
    severity: error
    message: Mention of the internal project is forbidden
```

Every domain is optional. An absent domain leaves its rule inactive
(status `not_applicable` in the report). `severity` is allowed in any
domain; without it the domain uses the default value from the table
below. The fields `block_on_failure` and `block_above` work only in
`version: 2` files; in `version: 1`, `block_on_failure` on secrets
stays informational, as before.

## Domains and checks

The checks run over scan.json (rep) and the root file system. An "empty
fact" (a scan section is absent or gives no data) yields the status
`unknown`, not `pass`: what was not checked does not count as safe.

| Domain | Rule ID | What it checks | Facts | Default severity |
|---|---|---|---|---|
| secrets | POL-SECRETS-EXPOSED | no entries with status fail in `rep["secrets"]` | rep | critical |
| mcp | POL-MCP-ALLOWLIST | every configured MCP server is in the allowlist | root files | error |
| instructions | POL-INSTRUCTIONS-AGENTS-MD | AGENTS.md or CLAUDE.md exists in the root | root files | warning |
| git | POL-GIT-SECRET-COMMITS | no tracked_secrets, and a pre-commit/pre-push hook with a secret scan exists | rep + `top_level[].extra` | critical |
| permissions | POL-PERMISSIONS-WILDCARD | no findings with check_id `CLAUDE_SETTINGS_PERMISSIONS_WILDCARD`, `CODEX_SANDBOX_DANGER`, `CODEX_APPROVAL_NEVER`, `OPENCODE_PERMISSIONS_DANGEROUS` in findings_detailed | rep | error |
| content | POL-CONTENT-BAN-PATTERNS | the banned patterns do not occur in text files | root files | error |
| harness_versions | POL-HARNESS-VERSIONS | the version of every required harness is inside its range | rep + `harnesses[].version` | error |
| required_skills | POL-REQUIRED-SKILLS | every required skill is installed | rep + `skills.entries[].name` | error |

The engine reads the MCP servers itself from `.mcp.json` (`mcpServers`),
`.claude/settings*.json` (`mcpServers`), `.codex/config.toml`
(`[mcp_servers.*]`, with tomllib when available) and `.cursor/mcp.json`.
The evidence carries only the server name and the file: command and env
never enter the report.

content.ban_patterns (and custom rules) scan only AGENTS.md, CLAUDE.md,
`.mcp.json` and `.claude/settings*.json` in the root, with a cap of
256 KB per file. The evidence is the file, the line and the match
itself: the match is banned text, not a secret.

harness_versions: a range is one operator (`>=`, `<=`, `>`, `<`, `==`)
and a semver-like string; the comparison is numeric, component by
component (`2.1` equals `2.1.0` and is less than `2.1.1`; non-numeric
suffixes such as `-beta` are ignored). A harness in the scan with
`version: null`, or missing from the scan, gets the status `unknown`,
not pass and not a violation. A version outside its range is a
violation with the evidence `{harness, version, required}`.

required_skills: a list of names; a skill missing from
`rep["skills"]["entries"]` is a violation. An empty skill list or an
absent section gives `unknown`: the scan collected no facts, and what
was not checked does not count as safe.

## Severity mapping

| Policy | Finding severity | Rule/violation status |
|---|---|---|
| critical | critical | fail |
| error | high | fail |
| warning | medium | warn |
| info | low | info |

Every violation carries a stable id (POL-\<DOMAIN\>-\<CHECK\> or the id
of a custom rule), the rule text, evidence (file/line/detail), severity
and message. The `version` field of each file goes into `policy_versions`
of the report. The same input and version give the same report
(deterministic: no timestamps, no traversal order).

## Exceptions

The `[policy]` section of `.agents-doctor.toml`:

```toml
[policy]
exceptions = { POL-MCP-ALLOWLIST = "local development environment" }
files = ["team.yml"]
```

`exceptions` is a map of rule_id → reason. The reason is mandatory: an
exception without a reason is applied but adds a warning. An exception
suppresses the whole rule: its violations move to `exceptions[]` of the
report and the rule gets the status `suppressed`. An exception with an
unknown rule_id gives a warning (it catches typos). `files` lists paths
to additional workspace-level YAML policies; they layer on top of the
ones passed in `--policy`.

## Layering

Several policy files apply in order: a file later in the list has
priority (team over corporate). For one domain, the last file that
defined it is in effect, as a whole and not field by field. A domain
defined only in an earlier file keeps working.

When one domain has different severities across the hierarchy, the
report gets a warning and the stricter one applies (critical > error >
warning > info). Custom rules accumulate over all files; the same id
gives a warning, and the later one wins.

Enforcement settings from v2 files merge on top of all files: `enabled`
is OR (any file with `enabled: true` turns enforcement on);
`default_action` and `unknown_action` take the stricter value when the
values conflict (block > warn), with a warning. An enforcement block in
a version: 1 file is ignored with a warning.

## Enforcement v2

The `version: 2` schema turns policy violations into exit codes for CI.
It is enough to add an `enforcement` block to `policy:`; v1 files work
as before (every exit is 0 after the report is written, and
`block_on_failure` is informational).

```yaml
version: 2

policy:
  name: enterprise-baseline
  enforcement:
    enabled: true            # on/off switch; false or absent = v1 behaviour
    default_action: block    # block | warn -- for domains without an explicit block_on_failure
    unknown_action: warn     # block | warn -- for rules in status unknown
  secrets:
    severity: critical
    block_on_failure: true   # now blocks
    block_above: high        # block on violations of level high and above (optional)
```

A rule blocks when:

- the domain set `block_on_failure: true`, and the domain's violations
  reach the `block_above` threshold (when it is set; "this level and
  above" on the finding severity scale: low < medium < high <
  critical); or
- a domain without an explicit `block_on_failure` has violations under
  `default_action: block`. An explicit `block_on_failure: false` turns
  blocking off for the domain even under `default_action: block`.

Custom rules follow `default_action`: they have no `block_on_failure`
or `block_above` of their own. A rule suppressed by an exception
(`suppressed`) does not block: the exception is stronger than
enforcement.

### Exit codes of the policy subcommand

| Code | Meaning |
|---|---|
| 0 | no violations, or enforcement is off |
| 1 | a blocking rule fired (the list is in `summary.enforcement.blocking_rules`) |
| 2 | configuration error: a broken or missing policy file |
| 3 | the check cannot run: scan.json cannot be read or has no root |
| 4 | strict enforcement: `unknown_action: block` and there are rules in status unknown |

The report is printed or written before the exit on 0, 1 and 4.
The report `summary` gets one more block:

```
enforcement  {enabled, action_taken, exit_code, blocking_rules}
```

`action_taken` is `block`, `warn` (there are violations, but they do
not block) or `none`.

`audit --policy` repeats the same logic: the compliance report is
embedded into scan.json; when the result is a block,
`policy: BLOCKED by N rule(s): …` is printed and the command returns 1
(4 when the block comes from unknown rules), always after scan.json is
written.

### CI: GitHub Actions

```yaml
- uses: actions/checkout@v4
- uses: vonavikon/agents-doctor@v2.1.1
  with:
    path: '.'
    policy: policies/enterprise.yml
    policy-enforcement: 'true'
```

The `policy-enforcement` input (default `'false'`): with `'true'`, the
exit code of the policy step is passed on to the job. Without it the
enforcement outcomes (1 and 4) stay advisory: the step writes the
report and exits zero. Configuration and scan errors (2, 3) fail the
job in both modes: the check did not run.

### Migration from v1 to v2

Add an `enforcement` block and set `version: 2`; v1 files keep working
without changes. While `enabled: false` (or the block is absent), the
behaviour is indistinguishable from v1: every exit code is 0 after the
report is written.

## Unknown is not safe

An unknown domain, an unknown field of a domain, an unknown top-level
key: each gives a warning in the report, and the value is ignored.
`name` and `description` inside `policy:` are metadata, not domains. An
invalid severity, a non-list in allowlist/ban_patterns, a non-boolean
flag: each gives a warning. Broken YAML raises PolicyError with the file
name and line; a policy is never applied in part.

## YAML without dependencies

PyYAML is optional (as for skill frontmatter). Without it a bundled
fallback parser of the same class as the TOML parser in config.py parses
the files: nested mappings by indentation, lists of `- item` (dictionary
items included, for custom_rules) and inline `[a, b]`, scalars
(bool/int/float/null, single and double quotes), `#` comments (whole
line and trailing). A tab in the indentation, an unclosed quote or
bracket, a duplicate key, a `- item` outside a list, `a: b: c`: each is
an error with the line number.

## Report

`evaluate_policies(rep, root, policy_files) -> dict`:

```
policy_versions   [{file, version}] in file order
policy_name       name of the last file that sets it
block_on_failure  flag of the secrets domain (informational, for CI)
rules_evaluated   [{id, domain, rule, status, severity, violations,
                    suppressed, source}]
violations        [{id, severity, status, message, rule, evidence}]
exceptions        [{id, reason, suppressed}]
warnings          [strings]
summary           {rules, pass, fail, warn, info, unknown, suppressed,
                    not_applicable, violations, by_severity,
                    enforcement}
```

Rule statuses: `pass`, `fail`, `warn`, `info` (by the severity mapping),
`unknown` (no facts), `suppressed` (exception), `not_applicable` (the
domain is not set, or is turned off). The markdown format
(`render_markdown`, `--format md`) is a table of rule / status /
violations / severity plus warnings, exceptions and the list of
violations.

Secrets never enter a policy and never enter the report: the secrets
check copies only the path, kind, mask and fingerprint from the scan;
MCP evidence is the server name and the file. Canary tests for this are
in tests/test_policies.py.

## Policy pack distribution

A policy is distributed in a marketplace package: the YAML file goes
into the package next to `plugin.json`; agents-doctor looks for
policies with the glob `policies/*.yml` in installed plugins and loads
them as the corporate level (`--policy` and `[policy] files` layer on
top). The format is the same as described above; the file name is a
slug (`corporate-baseline.yml`). The glob search itself is an
implementation detail; what is fixed here is the contract:
`policies/*.yml` files next to `plugin.json`, in the format of this
document.
