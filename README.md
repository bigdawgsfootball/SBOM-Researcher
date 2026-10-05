# SBOM-Researcher

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/bigdawgsfootball/SBOM-Researcher/badge)](https://scorecard.dev/viewer/?uri=github.com/bigdawgsfootball/SBOM-Researcher)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/9346/badge)](https://www.bestpractices.dev/projects/9346)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/bigdawgsfootball/SBOM-Researcher)

SBOM-Researcher reads CycloneDX or SPDX JSON software bills of materials
(SBOMs), queries OSV for package vulnerabilities, and writes text and JSON
results to help teams assess open-source software risk.

## What it does

- Extracts package URLs (PURLs), versions, and available license data from
  CycloneDX components and SPDX package external references.
- Uses OSV's `/v1/querybatch` API to query packages in batches, follows
  per-query pagination, and retrieves full vulnerability records by ID.
- Calculates CVSS v3.0, v3.1, and v4.0 base scores from OSV-provided vectors.
  CVSS v4.0 output uses its own metrics, including Attack Requirements and
  vulnerable/subsequent system impacts.
- For findings with CVE identifiers, checks CISA Known Exploited Vulnerabilities
  (KEV) status through the NVD CVE API and retrieves EPSS probabilities from
  FIRST. These online checks do not require a downloaded catalog or local cache.
- Marks a finding `ELEVATED` if any associated CVE is in KEV or the highest
  available EPSS score meets the configured threshold. KEV and EPSS are
  prioritization context; they do not change the CVSS score.
- Displays progress while files are loaded, components are extracted, and
  vulnerability and exploitation-signal lookups are performed.

OSV records that have no CVE ID or CVE alias remain findings, but cannot receive
KEV/EPSS enrichment. External lookup failures are reported as warnings; their
signals are not treated as negative results.

### Interpreting EPSS

The [Exploit Prediction Scoring System (EPSS)](https://www.first.org/epss/) is
FIRST's estimate, from 0 to 1, of the probability that a published CVE will be
exploited in the wild during the next 30 days. For example, an EPSS score of
`0.30` means an estimated 30% probability for that period; it is not a CVSS
severity score, a measure of impact, or a guarantee that exploitation will or
will not occur. It estimates general exploitation likelihood, not whether the
vulnerability is exploitable in a particular deployment.

This script uses the highest available EPSS score among a finding's CVE aliases.
At or above `-EPSSWarningThreshold`, that score contributes an `ELEVATED`
priority reason; a score exactly equal to the threshold also qualifies. The
default threshold of `0.3` is a configurable prioritization choice, not an
official FIRST boundary. A score below the threshold does not mean the finding
is safe or unimportant. `STANDARD` means the available checks did not trigger
the configured elevation rule; `UNAVAILABLE` means the external signal could
not be checked; and `NOT APPLICABLE` means the OSV finding had no CVE to check.
KEV membership independently elevates a finding.

In the current outputs, an EPSS score is included in `ExploitationReasons`
when it meets or exceeds the threshold. Lower EPSS values and EPSS percentiles
are not included in the compact vulnerability output.

## Inputs and scope

`-SBOMPath` can be a single JSON SBOM or a directory. For a directory, the
script examines `.json` files directly in that directory (not recursively); a
directory may contain both CycloneDX and SPDX documents. Keep the output
directory separate from the input directory so generated files are not
mistaken for input SBOMs on a later run.

The parser currently expects CycloneDX package data in `components` and SPDX
package data in `packages`, with package PURLs available in the formats the
script recognizes. It does not query OSV for CycloneDX operating-system
components; their name, version, and description are written to the text
report. Unsupported CycloneDX component types are noted in the report.

## Usage

The script currently ends with a sample call to `SBOMResearcher`. Edit that
final invocation in `SBOMResearcher.ps1` for your input path, project name,
output directory, and options, then run the script:

```powershell
.\SBOMResearcher.ps1
```

The function call has this form:

```powershell
SBOMResearcher `
  -SBOMPath "C:\path\to\sbom.json" `
  -ProjectName "ExampleProject" `
  -wrkDir "C:\path\to\reports" `
  -minScore 7.0 `
  -ListAll $false `
  -PrintLicenseInfo $true `
  -EPSSWarningThreshold 0.3
```

| Parameter | Required | Description |
| --- | --- | --- |
| `-SBOMPath` | Yes | Path to one SBOM JSON file or a directory of SBOM JSON files. |
| `-ProjectName` | Yes | Project label used in report filenames. |
| `-wrkDir` | Yes | Directory where generated reports are written. |
| `-minScore` | Yes | Minimum CVSS score for scored findings to include; findings without a CVSS score are still included. |
| `-ListAll` | No | Defaults to `$false`. When true, writes a line for components where OSV found no vulnerabilities. |
| `-PrintLicenseInfo` | No | Defaults to `$false`. Includes license summaries and writes the categorized license JSON file. |
| `-EPSSWarningThreshold` | No | Defaults to `0.3`; valid range is 0 through 1. EPSS at or above this value elevates a CVE-linked finding. |

### `-minScore` behavior

Scored findings below `-minScore` are omitted from the vulnerability report.
Findings without an assessed CVSS score are **still included regardless of
`-minScore`**, so a potentially important unscored finding is not silently
excluded. KEV/EPSS priority is supplementary and does not override this
inclusion behavior.

## Output files

The files are written under `-wrkDir` using `-ProjectName` as their prefix:

- `<ProjectName>_report.txt` — human-readable report with affected component
  versions, OSV vulnerability details, fixed-version information, CVSS score
  and vector metrics, exploitation-priority warnings, and component locations.
- `<ProjectName>_vulns.json` — vulnerability records grouped by affected
  component. Each finding includes its CVE IDs and the compact
  `ExploitationPriority` and `ExploitationReasons` fields. CVSS vector
  properties are version-specific: CVSS 3.x findings contain Scope and C/I/A
  metrics, while CVSS 4.0 findings contain Attack Requirements and vulnerable/
  subsequent-system impact metrics.
- `<ProjectName>_locs.json` — SBOM-file locations for components with reported
  vulnerabilities.
- `<ProjectName>_license.json` — created when `-PrintLicenseInfo` is enabled for
  supported SBOM input; lists licenses categorized by the script's built-in
  low-, medium-, high-action, or unmapped lists.

The vulnerability JSON and location JSON are written when at least one
vulnerability is included in the report. A CVE may appear more than once when
distinct OSV advisory records reference it or when multiple component versions
are affected; each finding remains associated with its component and OSV record.

CycloneDX component licenses include the component's declared license IDs,
expressions, or names, separated by semicolons. A component with no declaration
is marked `NOASSERTION`. The built-in license action categories are indicators,
not legal advice; `UNMAPPED` means the license identifier is not in the script's
lists, not that the license is prohibited.

## Data sources and connectivity

The script requires network access to:

- [OSV](https://osv.dev/) for package vulnerability queries and full records.
- [NVD](https://nvd.nist.gov/developers/vulnerabilities) for CISA KEV fields
  associated with CVEs.
- [FIRST EPSS](https://www.first.org/epss/) for EPSS probability estimates.

If NVD or FIRST is unavailable, the script warns and reports the corresponding
signal as unavailable. It does not download or persist vulnerability catalogs.

## Development and tests

Tests use Pester and cover CVSS scoring, version selection, license reporting,
OSV batch queries, CVE exploitation-signal enrichment, progress reporting, CVSS
metric mapping, and CycloneDX license attribution. Run the tests from the
repository root with:

```powershell
Invoke-Pester -Path .\tests
```

CVSS v3.0, v3.1, and v4.0 scoring is validated against FIRST calculator
examples. The project is under active development; review findings in their
component and deployment context before making approval decisions.
