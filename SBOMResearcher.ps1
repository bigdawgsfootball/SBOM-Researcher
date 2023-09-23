function ConvertTo-Version {
    param (
        [Parameter(Mandatory=$true)]
        [string]$VersionString
    )
    # Split the string by dot or any non-digit character
    $parts = $VersionString -split '[\.\D]+'
    # Create a new string with the parts
    return ($parts -join '.')
}

function Get-HighVersion {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true)][string]$High,
        [Parameter(Mandatory=$true)][string]$Compare
    )
    #compares 2 Version objects and returns the 'newer' one
    #-gt doesn't work with empty strings, so need to use "UNSET" to indicate ""
    if ($High -eq "") {
        $High = "UNSET"
    }
    if ($Compare -eq "") {
        $Compare = "UNSET"
    }

    if ($Compare -ne "UNSET") {
        if ($High -eq "UNSET") {
            $High = $Compare
        } elseif ($High -ne "Unresolved version") {
            try {
                #sometimes the version string can't be cast correctly
                if ([System.Version]$Compare -gt [System.Version]$High) {
                    $High = $Compare
                }
            } catch {
                try {
                    $Compare2 = ConvertTo-Version($Compare)
                    if ([System.Version]$Compare2 -gt [System.Version]$High) {
                        $High = $Compare2
                    }
                } catch {
                    $High = "Unresolved version"
                }
            }
        }
    } else {
        $High = "Unresolved version"
    }

    Return $High
}

function PrintLicenses {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][object[]]$alllicenses
    )

    $licstr = ""
    $LowRisk = ""
    $MedRisk = ""
    $HighRisk = ""

    #Low Risk licenses generally do not require any action / attribution to include or modify the code
    $LowRiskLicenses = @("MIT", "Apache-2.0", "ISC", "BSD-4-Clause", "BSD-3-Clause", "BSD-2-Clause", "BSD-1-Clause", "BSD-4-Clause-UC", "Unlicense", "Zlib", "Libpng", "Wtfpl-2.0", "OFL-1.1", "Edl-v10", "CCA-4.0", "0BSD", "CC0-1.0", "BSD-2-Clause-NetBSD", "Beerware", "PostgreSQL", "OpenSSL", "W3C", "HPND", "curl", "NTP", "WTFPL")
    #Medium Risk licenses require some action in order to use or modify the code in a deritive work
    $MedRiskLicenses = @("EPL-2.0", "MPL-1.0", "MPL-1.1", "MPL-2.0", "EPL-1.0", "CDDL-1.1", "AFL-2.1", "CPL-1.0", "CC-BY-4.0", "Artistic-2.0", "CC-BY-3.0", "AFL-3.0", "BSL-1.0", "OLDAP-2.8", "Python-2.0", "Ruby")
    #High Risk licenses often require actions that we may not be able to take, like applying a copyright on the deritive work or applying the same license to the deritive work
    $HighRiskLicenses = @("LGPL-2.0-or-later", "LGPL-2.1-or-later", "GPL-2.0-or-later", "GPL-2.0-only", "GPL-3.0-or-later", "GPL-2.0+", "GPL-3.0+", "LGPL-2.0", "LGPL-2.0+", "LGPL-2.1", "LGPL-2.1+", "LGPL-3.0", "LGPL-3.0+", "GPL-2.0", "CC-BY-3.0-US", "CC-BY-SA-3.0", "GFDL-1.2", "GFDL-1.3", "GPL-3.0", "GPL-1.0", "GPL-1.0+", "IJG", "AGPL-3.0", "CC-BY-SA-4.0")

    #determine all the license risk categories
    foreach ($lic in $alllicenses) {
        if ($LowRiskLicenses.Contains($lic)) {
            $LowRisk += $lic + "   "
        } elseif ($MedRiskLicenses.Contains($lic)) {
            $MedRisk += $lic + "   "
        } elseif ($HighRiskLicenses.Contains($lic)) {
            $HighRisk += $lic + "   "
        } else {
            $licstr += $lic + "   "
        }
    }

    #Print out all unique licenses found in the SBOM
    Write-Output "------------------------------------------------------------" | Out-File -FilePath $outfile -Append
    Write-Output "-   Low Risk Licenses found in this SBOM:  $LowRisk" | Out-File -FilePath $outfile -Append
    Write-Output "-   Medium Risk Licenses found in this SBOM:  $MedRisk" | Out-File -FilePath $outfile -Append
    Write-Output "-   High Risk Licenses found in this SBOM:  $HighRisk" | Out-File -FilePath $outfile -Append
    Write-Output "-   Unmapped Licenses found in this SBOM:  $licstr" | Out-File -FilePath $outfile -Append
    Write-Output "------------------------------------------------------------" | Out-File -FilePath $outfile -Append
}

function Get-VersionFromPurl {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory=$true)][string]$purl
    )

    if ($purl -like "*@*") {
        $parts = $purl.Split("@")
        return $parts[1]
    } else {
        return ""
    }
}

function Get-NameFromPurl {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory=$true)][string]$purl
    )

    if ($purl -like "*@*") {
        $parts = $purl.Split("@")
        $pieces = $parts[0].split("/")
        return $pieces[1]
    } else {
        return ""
    }
}
function Get-VulnList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][PSObject]$purls,
        [Parameter(Mandatory=$true)][string]$outfile,
        [Parameter(Mandatory=$true)][boolean]$ListAll
    )
    #this function reads through an sbom and pulls out each component listed
    #it then queries the OSV DB using the purl of each component to find all vulnerabilities per component
    #for each vulnerability, it will print the summary, deatils, vuln id, fixed version, link to CVSS score calculator, and license info
    #at the end of the component, it will print the recommended upgrade version if all vulnerabilities have been addressed in upgrades
    $fixedHigh = "UNSET"

    foreach ($purl in $purls) {
        #We don't know the high water mark for fixed versions until after all have been evaluated, so need to print $fixedHigh before the next component starts
        if ($fixedHigh -ne "UNSET") {
            Write-Output "##############" | Out-File -FilePath $outfile -Append
            Write-Output "-   Recommended Version to upgrade to that addresses all vulnerabilities: $fixedHigh" | Out-File -FilePath $outfile -Append
            Write-Output "##############" | Out-File -FilePath $outfile -Append
            $fixedHigh = "UNSET"
        }

        # Build the JSON body for the OSV API query
        $body = @{
            "version" = Get-VersionFromPurl($purl)
            "package" = @{
                "purl" = $purl
            }
        } | ConvertTo-Json

        # Invoke the OSV API with the JSON body and save the response
        try {
            $response = Invoke-WebRequest -uri "https://api.osv.dev/v1/query" -Method POST -Body $body -UseBasicParsing -ContentType 'application/json'
        } catch {
            Write-Output "StatusDescription:" $_.Exception.Message
        }

        # Check if the response has any vulnerabilities
        if ($response.Content.length -gt 2) {
            $name = Get-NameFromPurl($purl)
            $version = Get-VersionFromPurl($purl)

            # Print the component name and version
            Write-Output "------------------------------------------------------------" | Out-File -FilePath $outfile -Append
            Write-Output "-   Component: $name ($version)" | Out-File -FilePath $outfile -Append
            Write-Output "------------------------------------------------------------" | Out-File -FilePath $outfile -Append

            $vulns = $response.Content | ConvertFrom-Json

            # Loop through each vulnerability in the response
            foreach ($vulnerability in $vulns.vulns) {

                #build uri string to display calculated score and impacted areas
                if ($vulnerability | Get-Member "Severity") {
                    if ($vulnerability.severity.score.contains("3.0")) {
                        #CVSS 3.0
                        $scoreuri = "https://www.first.org/cvss/calculator/3.0#"
                        $scoreuri = $scoreuri + $vulnerability.severity.score
                    } elseif ($vulnerability.severity.score.contains("3.1")) {
                        #CVSS 3.1
                        $scoreuri = "https://www.first.org/cvss/calculator/3.1#"
                        $scoreuri = $scoreuri + $vulnerability.severity.score
                    } else {
                        #if this string shows up in any output file, need to build a new section for the new score version
                        $scoreuri = "UPDATE CODE FOR THIS CVSS SCORE TYPE -> $vulnerability.severity.score"
                    }

                } else {
                    $scoreuri = ""
                }

                # Get the vulnerability id, summary, details, and fixed version
                #id is used to search OSV manually for this package
                $id = $vulnerability.id
                $summary = $vulnerability.summary
                $details = $vulnerability.details
                #if fixed is set, this would be the version of the package that addresses the vulnerability
                #there can be multiple fixed versions, some based on hashes in the repo, you don't want that one
                foreach ($affected in $vulnerability.affected.ranges) {
                    if (($affected.type -ne "GIT") -and ($null -ne $affected.events[1].fixed)) {
                        $fixed = $affected.events[1].fixed
                    }
                }

                if (($fixed -eq "") -or ($null -eq $fixed)) {
                    $fixed = "UNSET"
                }
                $fixedHigh = Get-HighVersion -High $fixedHigh -Compare $fixed

                # Print the vulnerability details
                # some vulnerabilities do not return a summary or fixed version
                Write-Output "Vulnerability: $id" | Out-File -FilePath $outfile -Append
                if ($null -ne $summary) {
                    Write-Output "Summary: $summary" | Out-File -FilePath $outfile -Append
                }
                Write-Output "Details:  $details" | Out-File -FilePath $outfile -Append
                Write-Output "Fixed Version:  $fixed" | Out-File -FilePath $outfile -Append
                if ($scoreuri -ne "") {
                    Write-Output "Score page:  $scoreuri" | Out-File -FilePath $outfile -Append
                }
                Write-Output "License info:  $($pkglicenses.license.id)" | Out-File -FilePath $outfile -Append
                Write-Output "" | Out-File -FilePath $outfile -Append
            }
        } else {
            if ($ListAll) {
                Write-Output "OSV found no vulnerabilities for $purl licensed with $($pkglicenses.license.id)" | Out-File -FilePath $outfile -Append
            }
        }
    }

    #In case the last package has multiple fixed versions, print the high water mark for fixed versions after all have been evaluated
    if ($fixedHigh -ne "UNSET") {
        Write-Output "##############" | Out-File -FilePath $outfile -Append
        Write-Output "-   Recommended Version to upgrade to that addresses all vulnerabilities: $fixedHigh" | Out-File -FilePath $outfile -Append
        Write-Output "##############" | Out-File -FilePath $outfile -Append
        $fixedHigh = "UNSET"
    }

}

function Get-SBOMType {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true)][string]$SBOM
    )

    if ($SBOM -like "*CycloneDX*") {
        Return "CycloneDX"
    } elseif ($SBOM -like "*SPDX*") {
        Return "SPDX"
    } else {
        Return "Unsupported"
    }

}

function Get-CycloneDXComponentList {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true)][PSObject]$SBOM,
        [Parameter(Mandatory=$true)][PSObject]$allLicenses
    )

    foreach ($package in $SBOM.components) {
        $type = $package.type
        $pkgLicenses = $package.licenses

        $found = $false
        #Pull out all the unique licenses found in the SBOM as you go. The full list will be printed together in the report.
        foreach ($license in $pkgLicenses) {
            foreach ($complicense in $allLicenses) {
                if ($complicense -eq $license.license.id) {
                    $found = $true
                }
            }
            if (!($found)) {
                $allLicenses += $license.license.id
            } else {
                $found = $false
            }
        }

        if ($type -eq "library" -or $type -eq "framework") {
            # Get the component purl
            $allpurls += $package.purl
        } elseif ($type -eq "operating-system") {
            #OSV does not return good info on Operating Systems, just need to report OS and version for investigation
            $name = $package.name
            $version = $package.version
            $desc = $package.description

            # Print the OS name and version
            Write-Output "------------------------------------------------------------" | Out-File -FilePath $outfile -Append
            Write-Output "-   OS Name:  $name" | Out-File -FilePath $outfile -Append
            Write-Output "-   OS Version: $version" | Out-File -FilePath $outfile -Append
            Write-Output "-   OS Descriptiom:  $desc" | Out-File -FilePath $outfile -Append
            Write-Output "------------------------------------------------------------" | Out-File -FilePath $outfile -Append
        } else {
            #If this pops on the output, need to add code to query OSV for this ecosystem
            Write-Output "Not capturing $type"
        }
    }

    if ($PrintLicenseInfo) {
        PrintLicenses($allLicenses)
    }

    Return $allpurls
}

function Get-SPDXComponentList {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true)][PSObject]$SBOM,
        [Parameter(Mandatory=$true)][PSObject]$allLicenses
    )

    foreach ($package in $SBOM.packages) {
        $decLicense = $package.licenseDeclared
        $conLicense = $package.licenseConcluded

        $found = $false
        #Pull out all the unique licenses found in the SBOM as you go. The full list will be printed together in the report.
        foreach ($complicense in $allLicenses) {
            if (($complicense -eq $decLicense) -and ($decLicense -ne "NOASSERTION") -and ($null -ne $decLicense)) {
                $found = $true
            }
        }

        if (!($found) -and ($null -ne $decLicense)) {
            $allLicenses += $decLicense
        } else {
            $found = $false
        }

        $found = $false
        foreach ($complicense in $allLicenses) {
            if (($complicense -eq $conLicense) -and ($conLicense -ne "NOASSERTION") -and ($null -ne $conLicense)) {
                $found = $true
            }
        }

        if (!($found) -and ($null -ne $conLicense)) {
            $allLicenses += $conLicense
        } else {
            $found = $false
        }

        foreach ($refType in $package.externalRefs) {
            if ($refType.referenceType -eq "purl") {
                # Get the component purl
                $allpurls += $refType.referenceLocator
            }
        }

    }

    if ($PrintLicenseInfo) {
        PrintLicenses($allLicenses)
    }

    Return $allpurls
}

function SBOMResearcher {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$SBOMPath, #Path to a directory of SBOMs, or path to a single SBOM
        [Parameter(Mandatory=$true)][string]$wrkDir, #Directory where reports will be written, do NOT make it the same as $SBOMPath
        [Parameter(Mandatory=$false)][boolean]$ListAll=$false, #flag to write all components found in report, even if no vulnerabilities found
        [Parameter(Mandatory=$false)][boolean]$PrintLicenseInfo=$false #flag to print license info in report
    )

    #Begin main script
    if (get-item $wrkDir) {
       #dir exists
    } else {
        mkdir $wrkDir
    }

    $allLicenses = @()
    $allpurls = @()

    $argType = Get-Item $SBOMPath
    if ($argType.PSIsContainer) {
        #directory
        #call Get-Vulns with each file in the directory
        #if files other than sboms are in the directory, this could cause errors
        #that's why it's best not to have the output dir the same as the sbom dir
        foreach ($file in $argtype.GetFiles()) {
            $outfile = $wrkDir + "\" + $file.BaseName + "_vulns.txt"
            Write-Output $file.FullName | Out-File -FilePath $outfile
            Write-Output "=====================================================================================" | Out-File -FilePath $outfile -Append
            $SBOM = Get-Content -Path $file.fullname | ConvertFrom-Json
            $SBOMType = Get-SBOMType -SBOM $SBOM
            $allpurls = @()
            switch ($SBOMType) {
                "CycloneDX" { $allpurls = Get-CycloneDXComponentList $SBOM $allLicenses }
                "SPDX" { $allpurls = Get-SPDXComponentList $SBOM $allLicenses }
                "Unsupported" { Write-Output "This SBOM type is not supported" | Out-File -FilePath $outfile -Append }
            }
            if ($null -ne $allpurls) {
                Get-VulnList -purls $allpurls -outfile $outfile -ListAll $ListAll
            }
            }
    } else {
        #file
        $outfile = $wrkDir + "\" + $argtype.name.replace(".json","") + "_vulns.txt"
        Write-Output $SBOMPath | Out-File -FilePath $outfile
        Write-Output "=====================================================================================" | Out-File -FilePath $outfile -Append
        $SBOM = Get-Content -Path $SBOMPath | ConvertFrom-Json
        $SBOMType = Get-SBOMType -SBOM $SBOM
        $allpurls = @()
        switch ($SBOMType) {
            "CycloneDX" { $allpurls = Get-CycloneDXComponentList $SBOM $allLicenses }
            "SPDX" { $allpurls = Get-SPDXComponentList $SBOM $allLicenses }
            "Unsupported" { Write-Output "This SBOM type is not supported" | Out-File -FilePath $outfile -Append }
        }
        if ($null -ne $allpurls) {
            Get-VulnList -purls $allpurls -outfile $outfile -ListAll $ListAll
        }
    }
}

#SBOMResearcher -SBOMPath "C:\Temp\SBOMResearcher\sboms" -wrkDir "C:\Temp\SBOMResearcher\reports" -PrintLicenseInfo $true
