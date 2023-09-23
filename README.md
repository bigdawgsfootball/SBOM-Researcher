# SBOM-Researcher


## Description
This script takes a path to an SBOM, or a directory of SBOMs, pulls out each
package referenced, and queries the OSV (Open Source Vulnerability) DB
managed by Google. It will then report back with the list of vulnerabilities
published for each package, and will provide a link to a page detailing the
CVSS score for each vulnerability if the CVSS score was provided.

Each vulnerability in the report will list the Vulnerability ID, Summary,
Details, Fixed Version and a calculated CVSS Score link, if supplied.

A rollup summary for each component in the report will indicate if there is a Version
you could upgrade to that will address all vulnerabilities.

A rollup summary at the end of the report can indicate (if commandline option provided)
an assessed risk level of all open source licenses that were found.

Has been tested reasonably so far against CycloneDX formated SBOMs.
This is the initial attempt for including SPDX formated SBOMs.
Your SBOMPath may include a mix of CycloneDX and SPDX SBOMs.

## Usage
SBOMResearcher -SBOMPath "_{Path to SBOM File or Directory}_" -wrkDir
"_{Path to Directory for output files}_" [Optional]-ListAll $true [Optional]-PrintLicenseInfo $true\
\
It's best if the -wrkDir path is different from the -SBOMPath \
Currently fileshare.resource.jwac.mil\temp\SBOMResearch\ _{ProjectName}_ is
a good place for -wrkDir

The Optional -ListAll parameter will print every purl evaluated into the
output file, even if no vulnerabilities are found in it. If not included,
the default is to only print vulnerabilities found

## Best Practices enforcement
SBOM-Researcher is evaluated against the default set of PSScriptAnalyzer
rules. All rules are enforced. \
Help documentation limited to the Usage section and comments in code.\
Pester tests implemented against Get-HighVersion and PrintLicenses functions.

## Project status
Under active development
