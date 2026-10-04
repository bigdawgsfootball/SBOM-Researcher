BeforeAll {
    . .\SBOMResearcher.ps1
}

Describe 'Get-OSVQueryResult' {
    BeforeEach {
        $script:batchRequestCount = 0
        Mock Write-Progress {}
    }

    It 'preserves query ordering and paginates only results with a page token' {
        $purls = @(
            [PSCustomObject]@{ purl = 'pkg:npm/first@1.0.0' }
            [PSCustomObject]@{ purl = 'pkg:npm/second@2.0.0' }
        )

        Mock Invoke-WebRequest {
            $script:batchRequestCount++
            $request = $Body | ConvertFrom-Json
            if ($script:batchRequestCount -eq 1) {
                $request.queries.Count | Should -Be 2
                return [PSCustomObject]@{
                    Content = '{"results":[{"vulns":[{"id":"OSV-1"}],"next_page_token":"first-page"},{"vulns":[{"id":"OSV-2"}]}]}'
                }
            }

            $request.queries.Count | Should -Be 1
            $request.queries[0].package.purl | Should -Be 'pkg:npm/first@1.0.0'
            $request.queries[0].page_token | Should -Be 'first-page'
            return [PSCustomObject]@{
                Content = '{"results":[{"vulns":[{"id":"OSV-3"}]}]}'
            }
        } -ParameterFilter { $Uri -eq 'https://api.osv.dev/v1/querybatch' }

        $results = Get-OSVQueryResult -Purls $purls

        $script:batchRequestCount | Should -Be 2
        $results.Count | Should -Be 2
        @($results[0].VulnerabilityIds) | Should -Be @('OSV-1', 'OSV-3')
        @($results[1].VulnerabilityIds) | Should -Be @('OSV-2')
    }

    It 'converts Cargo purls to crates.io in the batch request' {
        $purls = @([PSCustomObject]@{ purl = 'pkg:cargo/example@1.0.0' })

        Mock Invoke-WebRequest {
            $request = $Body | ConvertFrom-Json
            $request.queries[0].package.purl | Should -Be 'pkg:crates.io/example@1.0.0'
            return [PSCustomObject]@{ Content = '{"results":[{"vulns":[]}]}' }
        } -ParameterFilter { $Uri -eq 'https://api.osv.dev/v1/querybatch' }

        $results = Get-OSVQueryResult -Purls $purls

        $results.Count | Should -Be 1
        $results[0].VulnerabilityIds.Count | Should -Be 0
    }

    It 'splits requests at the 1000-query API limit' {
        $purls = @(
            1..1001 | ForEach-Object {
                [PSCustomObject]@{ purl = "pkg:npm/package$_@1.0.0" }
            }
        )
        $script:batchSizes = [System.Collections.Generic.List[int]]::new()

        Mock Invoke-WebRequest {
            $request = $Body | ConvertFrom-Json
            $script:batchSizes.Add($request.queries.Count) | Out-Null
            $results = @(
                for ($i = 0; $i -lt $request.queries.Count; $i++) {
                    @{ vulns = @() }
                }
            )
            return [PSCustomObject]@{
                Content = (@{ results = $results } | ConvertTo-Json -Depth 5 -Compress)
            }
        } -ParameterFilter { $Uri -eq 'https://api.osv.dev/v1/querybatch' }

        $results = Get-OSVQueryResult -Purls $purls

        $results.Count | Should -Be 1001
        @($script:batchSizes) | Should -Be @(1000, 1)
    }
}

Describe 'Get-OSVVulnerabilityDetail' {
    BeforeEach {
        Mock Write-Progress {}
    }

    It 'fetches each distinct vulnerability ID once' {
        $requestedIds = [System.Collections.Generic.List[string]]::new()

        Mock Invoke-WebRequest {
            $id = [System.Uri]$Uri
            $vulnerabilityId = $id.Segments[-1]
            $requestedIds.Add($vulnerabilityId) | Out-Null
            return [PSCustomObject]@{
                Content = (@{ id = $vulnerabilityId; summary = 'Test vulnerability' } | ConvertTo-Json -Compress)
            }
        } -ParameterFilter { $Uri -like 'https://api.osv.dev/v1/vulns/*' }

        $details = Get-OSVVulnerabilityDetail -VulnerabilityIds @('OSV-1', 'OSV-2', 'OSV-1')

        $requestedIds.Count | Should -Be 2
        $details.Keys.Count | Should -Be 2
        $details['OSV-1'].summary | Should -Be 'Test vulnerability'
    }

    It 'returns an empty lookup without making a request when there are no IDs' {
        Mock Invoke-WebRequest {
            throw 'No request should be made.'
        }

        $details = Get-OSVVulnerabilityDetail -VulnerabilityIds @()

        $details.Count | Should -Be 0
        Should -Invoke Invoke-WebRequest -Times 0
    }
}

Describe 'Get-CVEIdsForVulnerability' {
    It 'returns unique CVE IDs from the OSV ID and aliases only' {
        $vulnerability = [PSCustomObject]@{
            id = 'GHSA-example'
            aliases = @('CVE-2024-1234', 'CVE-2024-1234', 'PYSEC-2024-1', 'cve-2023-5678')
        }

        $cveIds = @(Get-CVEIdsForVulnerability -Vulnerability $vulnerability)

        $cveIds | Should -Be @('CVE-2024-1234', 'CVE-2023-5678')
    }

    It 'keeps an empty CVE result as an empty collection for non-CVE findings' {
        $vulnerability = [PSCustomObject]@{
            id = 'MAL-2024-1'
            aliases = @()
        }

        $cveIds = @(Get-CVEIdsForVulnerability -Vulnerability $vulnerability)
        $assessment = Get-VulnerabilityExploitationAssessment -CVEIds $cveIds -SignalsByCVE @{} -EPSSWarningThreshold 0.3

        $cveIds.Count | Should -Be 0
        $assessment.ExploitationPriority | Should -Be 'NOT APPLICABLE'
    }
}

Describe 'Get-CVEExploitationSignal' {
    BeforeEach {
        Mock Write-Progress {}
    }

    It 'uses batched NVD and EPSS responses to identify KEV and EPSS signals' {
        Mock Invoke-WebRequest {
            if ($Uri -like 'https://services.nvd.nist.gov/*') {
                return [PSCustomObject]@{
                    Content = '{"vulnerabilities":[{"cve":{"id":"CVE-2024-1234","cisaExploitAdd":"2024-02-01"}},{"cve":{"id":"CVE-2023-5678"}}]}'
                }
            }

            return [PSCustomObject]@{
                Content = '{"data":[{"cve":"CVE-2024-1234","epss":"0.35","percentile":"0.90","date":"2026-10-04"},{"cve":"CVE-2023-5678","epss":"0.12","percentile":"0.75","date":"2026-10-04"}]}'
            }
        }

        $signals = Get-CVEExploitationSignal -CVEIds @('CVE-2024-1234', 'CVE-2023-5678', 'CVE-2024-1234')

        $signals.Count | Should -Be 2
        $signals['CVE-2024-1234'].InCISAKEV | Should -BeTrue
        $signals['CVE-2024-1234'].KEVAddedDate | Should -Be '2024-02-01'
        $signals['CVE-2023-5678'].InCISAKEV | Should -BeFalse
        $signals['CVE-2024-1234'].EPSS | Should -Be 0.35
        $signals['CVE-2023-5678'].EPSS | Should -Be 0.12
        Should -Invoke Invoke-WebRequest -Times 1 -ParameterFilter { $Uri -like 'https://services.nvd.nist.gov/*' }
        Should -Invoke Invoke-WebRequest -Times 1 -ParameterFilter { $Uri -like 'https://api.first.org/*' }
    }

    It 'marks failed external lookups unavailable instead of treating them as negative signals' {
        Mock Invoke-WebRequest { throw 'network unavailable' }

        $signals = Get-CVEExploitationSignal -CVEIds @('CVE-2024-1234')

        $signals['CVE-2024-1234'].InCISAKEV | Should -BeNullOrEmpty
        $signals['CVE-2024-1234'].KEVLookupStatus | Should -Be 'Unavailable'
        $signals['CVE-2024-1234'].EPSSLookupStatus | Should -Be 'Unavailable'
    }

    It 'does not make external requests when there are no CVE identifiers' {
        Mock Invoke-WebRequest { throw 'No lookup should be made.' }

        $signals = Get-CVEExploitationSignal -CVEIds @()

        $signals.Count | Should -Be 0
        Should -Invoke Invoke-WebRequest -Times 0
    }
}

Describe 'Get-VulnerabilityExploitationAssessment' {
    It 'elevates findings for KEV membership or EPSS at the configured threshold' {
        $signals = @{
            'CVE-2024-1234' = [PSCustomObject]@{
                CVE = 'CVE-2024-1234'
                InCISAKEV = $false
                KEVAddedDate = $null
                KEVLookupStatus = 'Checked'
                EPSS = [decimal]0.3
                EPSSPercentile = [decimal]0.9
                EPSSDate = '2026-10-04'
                EPSSLookupStatus = 'Scored'
            }
            'CVE-2023-5678' = [PSCustomObject]@{
                CVE = 'CVE-2023-5678'
                InCISAKEV = $true
                KEVAddedDate = '2024-02-01'
                KEVLookupStatus = 'Checked'
                EPSS = [decimal]0.12
                EPSSPercentile = [decimal]0.75
                EPSSDate = '2026-10-04'
                EPSSLookupStatus = 'Scored'
            }
        }

        $assessment = Get-VulnerabilityExploitationAssessment -CVEIds @('CVE-2024-1234', 'CVE-2023-5678') -SignalsByCVE $signals -EPSSWarningThreshold 0.3

        $assessment.ExploitationPriority | Should -Be 'ELEVATED'
        $assessment.InCISAKEV | Should -BeTrue
        $assessment.EPSS | Should -Be 0.3
        $assessment.ExploitationReasons.Count | Should -Be 2
        $assessment.ExploitationReasons | Should -Contain 'EPSS 0.3 meets threshold of 0.3'
    }

    It 'does not elevate below-threshold EPSS or change the CVE-free assessment' {
        $signals = @{
            'CVE-2023-5678' = [PSCustomObject]@{
                CVE = 'CVE-2023-5678'
                InCISAKEV = $false
                KEVAddedDate = $null
                KEVLookupStatus = 'Checked'
                EPSS = [decimal]0.12
                EPSSPercentile = [decimal]0.75
                EPSSDate = '2026-10-04'
                EPSSLookupStatus = 'Scored'
            }
        }

        $standard = Get-VulnerabilityExploitationAssessment -CVEIds @('CVE-2023-5678') -SignalsByCVE $signals -EPSSWarningThreshold 0.3
        $notApplicable = Get-VulnerabilityExploitationAssessment -CVEIds @() -SignalsByCVE @{} -EPSSWarningThreshold 0.3

        $standard.ExploitationPriority | Should -Be 'STANDARD'
        $standard.InCISAKEV | Should -BeFalse
        $notApplicable.ExploitationPriority | Should -Be 'NOT APPLICABLE'
    }

    It 'does not report a negative KEV result when one CVE alias could not be checked' {
        $signals = @{
            'CVE-2024-1234' = [PSCustomObject]@{
                CVE = 'CVE-2024-1234'
                InCISAKEV = $false
                KEVAddedDate = $null
                KEVLookupStatus = 'Checked'
                EPSS = $null
                EPSSPercentile = $null
                EPSSDate = $null
                EPSSLookupStatus = 'Unavailable'
            }
            'CVE-2023-5678' = [PSCustomObject]@{
                CVE = 'CVE-2023-5678'
                InCISAKEV = $null
                KEVAddedDate = $null
                KEVLookupStatus = 'Unavailable'
                EPSS = $null
                EPSSPercentile = $null
                EPSSDate = $null
                EPSSLookupStatus = 'Unavailable'
            }
        }

        $assessment = Get-VulnerabilityExploitationAssessment -CVEIds @('CVE-2024-1234', 'CVE-2023-5678') -SignalsByCVE $signals -EPSSWarningThreshold 0.3

        $assessment.InCISAKEV | Should -BeNullOrEmpty
        $assessment.KEVLookupStatus | Should -Be 'Partial'
        $assessment.EPSSLookupStatus | Should -Be 'Unavailable'
    }
}

Describe 'PrintVulnerabilities exploitation output' {
    It 'highlights elevated findings and writes only compact exploitation fields to JSON' {
        $global:wrkDir = $TestDrive
        $global:ProjectName = 'SignalOutput'
        $global:outfile = Join-Path $TestDrive 'report.txt'
        $component = [PSCustomObject]@{
            Name = 'example'
            Version = '1.0.0'
            License = 'MIT'
            Recommendation = 'UNSET'
            Vulns = @(
                [PSCustomObject]@{
                    ID = 'OSV-2024-1'
                    Source = 'OSV'
                    CVEIds = @('CVE-2024-1234')
                    ExploitationPriority = 'ELEVATED'
                    ExploitationReasons = @('CISA KEV', 'EPSS 0.9998 exceeds threshold of 0.3')
                    Summary = 'Example finding'
                    Details = 'Details'
                    Fixed = '2.0.0'
                    ScoreURI = ''
                    Score = 8.7
                    Severity = 'HIGH'
                    CVSSVersion = '4.0'
                    AV = 'N'
                    AC = 'L'
                    AT = 'P'
                    PR = 'N'
                    UI = 'N'
                    VC = 'H'
                    VI = 'H'
                    VA = 'H'
                    SC = 'L'
                    SI = 'L'
                    SA = 'L'
                }
            )
        }

        $locations = @([PSCustomObject]@{ component = 'example'; version = '1.0.0'; file = 'example.json' })
        PrintVulnerabilities -allcomponents @($component) -componentLocations $locations

        $report = Get-Content -Raw -Path $global:outfile
        $report | Should -Match '!!! ELEVATED EXPLOITATION PRIORITY: CISA KEV, EPSS 0\.9998 exceeds threshold of 0\.3 !!!'
        $report | Should -Match 'CVSS Attack Requirements:\s+P'
        $report | Should -Match 'CVSS Vulnerable System C/I/A:\s+H / H / H'
        $report | Should -Not -Match 'CVSS Scope:'

        $vulnJson = Get-Content -Raw -Path (Join-Path $TestDrive 'SignalOutput_vulns.json') | ConvertFrom-Json
        $vulnerability = $vulnJson.Vulns[0]
        $vulnerability.CVEIds | Should -Be @('CVE-2024-1234')
        $vulnerability.ExploitationPriority | Should -Be 'ELEVATED'
        $vulnerability.ExploitationReasons | Should -Be @('CISA KEV', 'EPSS 0.9998 exceeds threshold of 0.3')
        $vulnerability.PSObject.Properties.Name | Should -Not -Contain 'CVEExploitationSignals'
        $vulnerability.PSObject.Properties.Name | Should -Not -Contain 'InCISAKEV'
        $vulnerability.PSObject.Properties.Name | Should -Not -Contain 'EPSS'
    }
}

Describe 'SBOM component extraction progress' {
    BeforeEach {
        $global:allpurls = @()
        $global:file = 'fixture.json'
        $global:PrintLicenseInfo = $false
        Mock Write-Progress {}
    }

    It 'reports progress while extracting CycloneDX components' {
        $componentLocations = [System.Collections.ArrayList]::new()
        $sbom = [PSCustomObject]@{
            components = @(
                [PSCustomObject]@{
                    type = 'library'
                    purl = 'pkg:npm/left-pad@1.0.0'
                    licenses = @()
                }
            )
        }

        $licenses = [System.Collections.ArrayList]::new()
        $null = Get-CycloneDXComponentList -SBOM $sbom -allLicenses $licenses -componentLocations ([ref]$componentLocations)

        Should -Invoke Write-Progress -Times 2 -ParameterFilter { $Id -eq 1 -and $Activity -eq 'Extracting CycloneDX components' }
    }

    It 'reports progress while extracting SPDX components' {
        $componentLocations = [System.Collections.ArrayList]::new()
        $sbom = [PSCustomObject]@{
            packages = @(
                [PSCustomObject]@{
                    licenseDeclared = 'MIT'
                    licenseConcluded = 'MIT'
                    versionInfo = '1.0.0'
                    externalRefs = @(
                        [PSCustomObject]@{
                            referenceType = 'purl'
                            referenceLocator = 'pkg:npm/left-pad@1.0.0'
                        }
                    )
                }
            )
        }

        $licenses = [System.Collections.ArrayList]::new()
        $null = Get-SPDXComponentList -SBOM $sbom -allLicenses $licenses -componentLocations ([ref]$componentLocations)

        Should -Invoke Write-Progress -Times 2 -ParameterFilter { $Id -eq 1 -and $Activity -eq 'Extracting SPDX components' }
    }
}

Describe 'CVSS vector output metrics' {
    It 'maps CVSS 4.0 metrics to their own fields instead of CVSS 3.x labels' {
        $metrics = Get-CVSSVectorMetric -Vector 'CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L'

        $metrics.CVSSVersion | Should -Be '4.0'
        $metrics.AV | Should -Be 'N'
        $metrics.AT | Should -Be 'P'
        $metrics.VC | Should -Be 'H'
        $metrics.SC | Should -Be 'L'
        $metrics.S | Should -Be ''
        $metrics.C | Should -Be ''
        $metrics.I | Should -Be ''
        $metrics.A | Should -Be ''
    }

    It 'preserves CVSS 3.x scope and CIA mappings' {
        $metrics = Get-CVSSVectorMetric -Vector 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N'

        $metrics.CVSSVersion | Should -Be '3.1'
        $metrics.AV | Should -Be 'N'
        $metrics.PR | Should -Be 'N'
        $metrics.S | Should -Be 'C'
        $metrics.C | Should -Be 'H'
        $metrics.I | Should -Be 'L'
        $metrics.A | Should -Be 'N'
    }
}

Describe 'CycloneDX component licenses' {
    BeforeEach {
        $global:allpurls = @()
        $global:file = 'licenses.json'
        $global:PrintLicenseInfo = $false
        Mock Write-Progress {}
    }

    It 'uses only each component licenses and retains multiple license declarations' {
        $componentLocations = [System.Collections.ArrayList]::new()
        $allLicenses = [System.Collections.ArrayList]::new()
        $global:outfile = Join-Path $TestDrive 'cyclonedx-licenses.txt'
        $global:wrkDir = $TestDrive
        $global:ProjectName = 'CycloneDXLicenses'
        $sbom = [PSCustomObject]@{
            components = @(
                [PSCustomObject]@{
                    type = 'library'
                    purl = 'pkg:npm/with-licenses@1.0.0'
                    licenses = @(
                        [PSCustomObject]@{ license = [PSCustomObject]@{ id = 'MIT' } }
                        [PSCustomObject]@{ expression = 'Apache-2.0 OR MIT' }
                    )
                }
                [PSCustomObject]@{
                    type = 'library'
                    purl = 'pkg:npm/no-license@1.0.0'
                    licenses = @()
                }
            )
        }

        $components = Get-CycloneDXComponentList -SBOM $sbom -allLicenses $allLicenses -componentLocations ([ref]$componentLocations)

        $components[0].license | Should -Be 'MIT; Apache-2.0 OR MIT'
        $components[1].license | Should -Be 'NOASSERTION'
        @($allLicenses) | Should -Be @('MIT', 'Apache-2.0 OR MIT')

        PrintLicenses -alllicenses $allLicenses
        $licenseReport = Get-Content -Raw -Path (Join-Path $TestDrive 'CycloneDXLicenses_license.json') | ConvertFrom-Json
        $licenseReport.Low.License | Should -Contain 'MIT'
        $licenseReport.Unmapped.License | Should -Contain 'Apache-2.0 OR MIT'
    }
}
