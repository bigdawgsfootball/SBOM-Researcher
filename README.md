# SBOM-Researcher

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/bigdawgsfootball/SBOM-Researcher/badge)](https://scorecard.dev/viewer/?uri=github.com/bigdawgsfootball/SBOM-Researcher)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/9346/badge)](https://www.bestpractices.dev/projects/9346)

## Description
This script takes a path to an SBOM, or a directory of SBOMs, pulls out each
package referenced, and queries the OSV (Open Source Vulnerability) DB
managed by Google. It will then report back with the list of vulnerabilities
published for each package, and will provide a link to a page detailing the
CVSS score for each vulnerability if the CVSS score was provided.

Each vulnerability in the report will list the Component Name and Version, and a list containing Vulnerability Name, Vulnerability Database Source, Summary, Details, Fixed Version if available, a link to a CVSS Score visualizer, a calculated CVSS Score, a breakdown of each CVSS Score components, a calculation of the CVSS Score severity, and any liscense info if the -PrintLicenseInfo parameter was $true for each vulnerability found of the component that exceeded the -minScore parameter.

A rollup summary for each component in the report will indicate if there is a Version you could upgrade to that will address all vulnerabilities.

A rollup summary at the end of the report can indicate (if commandline option provided) an assessed risk level of all open source licenses that were found.

All of the above information will be contained in the _ProjectName__report.txt output file. 2 other files are created which contain json representations of the vulnerabilities found and a mapping to the SBOM files they were found in. These were designed to be used in pipeline actions to support decision gates.

Has been tested reasonably so far against CycloneDX formated SBOMs.
This is the initial attempt for including SPDX formated SBOMs.
Your SBOMPath may include a mix of CycloneDX and SPDX SBOMs.

CVSS v3.0 and 3.1 are supported completely and validated against the FIRST.org calculator. CVSS 4.0 scores are incorporated and are being validated against the FIRST.org calculator.

## Usage
SBOMResearcher -SBOMPath "_{Path to SBOM File or Directory}_" -wrkDir
"_{Path to Directory for output files}_" [_Optional_]-ListAll true/false [_Optional_]-PrintLicenseInfo true/false -minScore decimal

It's best if the -wrkDir path is different from the -SBOMPath

The Optional -ListAll parameter will print every component evaluated into the
output file, even if no vulnerabilities are found in it. If not included,
the default is to only print components with vulnerabilities found that exceed the value of the -minScore parameter.

The minScore parameter will set the level of vulnerabilities to actually report on. Only want to see High / Critical? Pass 7.0 as minScore. Want to see all? Pass 0 as minScore.

## Best Practices enforcement
SBOM-Researcher is evaluated against the default set of PSScriptAnalyzer
rules. All rules are enforced.

Help documentation limited to the Usage section and comments in code.

Pester tests implemented against Convert-CVSSStringToBaseScore, Get-HighVersion and PrintLicenses functions.

## Project status
Under active development
