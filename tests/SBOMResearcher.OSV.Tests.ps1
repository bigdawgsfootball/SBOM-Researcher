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
