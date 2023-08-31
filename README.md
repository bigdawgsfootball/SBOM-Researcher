# SBOM-Researcher


## Description
This script takes a path to an SBOM, or a directory of SBOMs, pulls out each
package referenced, and queries the OSV (Open Source Vulnerability) DB
managed by Google. It will then report back with the list of vulnerabilities
published for each package, and will provide a link to a page detailing the
CVSS score for each vulnerability if the CVSS score was provided.

Each vulnerability in the report will list the Vulnerability ID, Summary,
Details, Fixed Version and a calculated CVSS Score link, if supplied.

Has only been tested so far against CycloneDX formated SBOMs.

## Usage
SBOMResearcher -SBOMPath "_{Path to SBOM File or Directory}_" -wrkDir
"_{Path to Directory for output files}_" [Optional]-ListAll $true\
\
It's best if the -wrkDir path is different from the -SBOMPath \
Currently fileshare.resource.jwac.mil\temp\SBOMResearch\ _{ProjectName}_ is
a good place for -wrkDir

The Optional -ListAll parameter will print every purl evaluated into the
output file, even if no vulnerabilities are found in it. If not included,
the default is to only print vulnerabilities found

## Best Practice enforcement
SBOM-Researcher is evaluated against the default set of PSScriptAnalyzer
rules. All rules are enforced. \
Help documentation limited to the Usage section and comments in code.

## Project status
Under active development
