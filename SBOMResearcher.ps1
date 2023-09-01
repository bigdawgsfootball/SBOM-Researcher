function Get-HighVersion {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true)][string]$High,
        [Parameter(Mandatory=$true)][string]$Compare
    )

    if ($Compare -ne "UNSET") {
        if ($High -eq "UNSET") {
            $High = $Compare
        } elseif ($High -ne "Unresolved version") {
            try {
                if ([System.Version]$Compare -gt [System.Version]$High) {
                    $High = $Compare
                }
            } catch {
                $High = "Unresolved version"
            }
        }
    } else {
        $High = "Unresolved version"
    }

    Return $High
}

function Get-VulnList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][PSObject]$SBOM,
        [Parameter(Mandatory=$true)][string]$outfile,
        [Parameter(Mandatory=$true)][boolean]$ListAll
    )

    $fixedHigh = "UNSET"

    foreach ($package in $SBOM.components) {
        $name = $package.name
        $version = $package.version
        $type = $package.type

        #We don't know the high water mark for fixed versions until after all have been evaluated, so need to print $fixedHigh before the next component starts
        if ($fixedHigh -ne "UNSET") {
            Write-Output "##############" | Out-File -FilePath $outfile -Append
            Write-Output "-   Recommended Version to upgrade to that addresses all vulnerabilities: $fixedHigh" | Out-File -FilePath $outfile -Append
            Write-Output "##############" | Out-File -FilePath $outfile -Append
            $fixedHigh = "UNSET"
        }

        if ($type -eq "library" -or $type -eq "framework") {
            # Get the component purl
            $purl = $package.purl

            # Build the JSON body for the OSV API query
            $body = @{
                "version" = $package.version
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
                    #there can be multiple fixed versions, some based on hashes in the repo, but you want the ECOSYSTEM one
                    foreach ($affected in $vulnerability.affected.ranges) {
                        if ($affected.type -eq "ECOSYSTEM") {
                            $fixed = $affected.events[1].fixed
                        }
                    }

                    if ($fixed -eq "") {
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
                    Write-Output "" | Out-File -FilePath $outfile -Append
                }
            } else {
                if ($ListAll) {
                    Write-Output "OSV found no vulnerabilities for $purl" | Out-File -FilePath $outfile -Append
                }
            }
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
}

function SBOMResearcher {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$SBOMPath,
        [Parameter(Mandatory=$true)][string]$wrkDir,
        [Parameter(Mandatory=$false)][boolean]$ListAll=$false
    )

    #Begin main script
    if (get-item $wrkDir) {
       #dir exists
    } else {
        mkdir $wrkDir
    }

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
            Get-VulnList -SBOM $SBOM -outfile $outfile -ListAll $ListAll
        }
    } else {
        #file
        $outfile = $File.DirectoryName + "\" + $file.BaseName + "_vulns.txt"
        Write-Output $file.FullName | Out-File -FilePath $outfile
        Write-Output "=====================================================================================" | Out-File -FilePath $outfile -Append
        $SBOM = Get-Content -Path $SBOMPath | ConvertFrom-Json
        Get-VulnList -SBOM $SBOM -outfile $outfile -ListAll $ListAll
    }
}

SBOMResearcher -SBOMPath "" -wrkDir ""