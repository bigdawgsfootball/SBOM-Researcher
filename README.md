# SBOM-Researcher


## Description
This script takes a path to an SBOM, or a directory of SBOMs, pulls out each
package referenced, and queries the OSV (Open Source Vulnerability) DB
managed by Google. It will then report back with the list of vulnerabilities
published for each package, and will provide a link to a page detailing the
CVSS score for each vulnerability if the CVSS score was provided.

Each vulnerability in the report will list the Vulnerability ID, Summary,
Details, Fixed Version, a calculated CVSS score, and a calculated CVSS Score link, if supplied.

A rollup summary for each component in the report will indicate if there is a Version
you could upgrade to that will address all vulnerabilities.

A rollup summary at the end of the report can indicate (if commandline option provided)
an assessed action level of all open source licenses that were found.

Also included in the output are JSON formated files showing all vulnerabilities found greater than the -minScore
parameter, and another JSON file showing which SBOM files they were found in.

Has been reasonably tested so far against CycloneDX formated SBOMs.
This is the initial attempt for including SPDX formated SBOMs.
Your SBOMPath may include a mix of CycloneDX and SPDX SBOMs.
## Usage
SBOMResearcher -SBOMPath "_{Path to SBOM File or Directory}_" -wrkDir
"_{Path to Directory for output files}_" [Optional]-ListAll boolean [Optional]-PrintLicenseInfo boolean [Optional]-useIonChannel boolean [Optional]-minScore boolean [Optional]-token string

It's best if the -wrkDir path is different from the -SBOMPath

The Optional -ListAll parameter will print every purl evaluated into the
output file, even if no vulnerabilities are found in it. If not included,
the default is to only print vulnerabilities found

The Optional -PrintLicenseInfo parameter will include all licenses found in the SBOM organized by action categories. This should be included in SBOMs for code we have developed.

The Optional -minScore parameter will set the minimum CVSS score of Ion Channel vulnerabilities that will be returned in the report. Default is 7.0, the lowest High CVSS score.


## Best Practices enforcement
SBOM-Researcher is evaluated against the default set of PSScriptAnalyzer
rules. All rules are enforced.

Help documentation limited to the Usage section, comments in code

Important functions identified as Get-HighVersion, PrintLicenses and Convert-CVSSStringToBaseScore.

Pester tests implemented against Get-HighVersion, PrintLicenses, Convert-CVSSStringToBaseScore, Get-PurlName, Get-PurlVersion, Get-SBOMType, Get-SPDXComponents, Get-CyclondDXComponents, and Get-Version functions.

## Project status
Under active development
