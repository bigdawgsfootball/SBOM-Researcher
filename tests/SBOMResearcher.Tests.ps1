# Import the function to test
. .\SBOMResearcher.ps1

# Define the test cases for Get-HighVersion
$testCases = @(
    @{High = "UNSET"; Compare = "UNSET"; Expected = "Unresolved version"}
    @{High = "UNSET"; Compare = "1.0.0"; Expected = "1.0.0"}
    @{High = "1.0.0"; Compare = "UNSET"; Expected = "Unresolved version"}
    @{High = "1.0.0"; Compare = "2.0.0"; Expected = "2.0.0"}
    @{High = "2.0.0"; Compare = "1.0.0"; Expected = "2.0.0"}
    @{High = "Unresolved version"; Compare = "UNSET"; Expected = "Unresolved version"}
    @{High = "Unresolved version"; Compare = "1.0.0"; Expected = "Unresolved version"}
    @{High = "1.0.0"; Compare = "Invalid"; Expected = "Unresolved version"}
)

# Run the tests for Get-HighVersion
Describe 'Get-HighVersion' {
    It 'returns <Expected> when High is <High> and Compare is <Compare>' -TestCases $testCases {
        param($High, $Compare, $Expected)
        Get-HighVersion -High $High -Compare $Compare | Should -Be $Expected
    }
}

# Define the test cases for Get-VulnList
$testCases = @(
    # Test case 1: Valid SBOM with one library component with one vulnerability
    @{
        SBOM = [PSCustomObject]@{
            components = @(
                [PSCustomObject]@{
                    name = "example"
                    version = "1.0.0"
                    type = "library"
                    purl = "pkg:npm/example@1.0.0"
                }
            )
        }
        outfile = "test1.txt"
        ListAll = $false
        ExpectedOutput = @(
            "------------------------------------------------------------"
            "-   Component: example (1.0.0)"
            "------------------------------------------------------------"
            "Vulnerability: OSV-2021-123"
            "Summary: Example vulnerability summary"
            "Details:  Example vulnerability details"
            "Fixed Version:  1.0.1"
            "Score page:  https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            ""
        )
    }
    # Test case 2: Valid SBOM with one operating-system component
    @{
        SBOM = [PSCustomObject]@{
            components = @(
                [PSCustomObject]@{
                    name = "Windows 10"
                    version = "10.0.19042"
                    type = "operating-system"
                    description = "Microsoft Windows 10 Home Edition"
                }
            )
        }
        outfile = "test2.txt"
        ListAll = $false
        ExpectedOutput = @(
            "------------------------------------------------------------"
            "-   OS Name:  Windows 10"
            "-   OS Version: 10.0.19042"
            "-   OS Descriptiom:  Microsoft Windows 10 Home Edition"
            "------------------------------------------------------------"
        )
    }
    # Test case 3: SBOM with multiple components
    @{
        SBOM = [PSCustomObject]@{
            components = @(
                [PSCustomObject]@{
                    name = "example"
                    version = "1.0.0"
                    type = "library"
                    purl = "pkg:npm/example@1.0.0"
                },
                [PSCustomObject]@{
                    name = "example 2"
                    version = "1.4.0"
                    type = "library"
                    purl = "pkg:npm/example 2@1.4.0"
                }
            )
        }
        outfile = "test3.txt"
        ListAll = $false
        ExpectedOutput = @(
            "------------------------------------------------------------"
            "-   Component: example (1.0.0)"
            "------------------------------------------------------------"
            "Vulnerability: OSV-2021-123"
            "Summary: Example vulnerability summary"
            "Details:  Example vulnerability details"
            "Fixed Version:  1.0.1"
            "Score page:  https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            ""
            "##############"
            "-   Recommended Version to upgrade to that addresses all vulnerabilities: 1.0.1"
            "##############"
            "------------------------------------------------------------"
            "-   Component: example 2 (1.4.0)"
            "------------------------------------------------------------"
            "Vulnerability: OSV-2021-123"
            "Summary: Example vulnerability summary"
            "Details:  Example vulnerability details"
            "Fixed Version:  1.0.1"
            "Score page:  https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            ""
            "Vulnerability: OSV-2021-123-2nd"
            "Summary: Example 2 vulnerability summary"
            "Details:  Example 2 vulnerability details"
            "Fixed Version:  1.4.1"
            "Score page:  https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            ""
        )
    }
)

# Mock the Invoke-WebRequest cmdlet to return a predefined response based on the purl
function Mock-InvokeWebRequest {
    param($uri, $Method, $Body, $UseBasicParsing, $ContentType)
    $purl = ($Body | ConvertFrom-Json).package.purl
    switch ($purl) {
        # Mock response for pkg:npm/example@1.0.0
        "pkg:npm/example@1.0.0" {
            return [PSCustomObject]@{
                Content = @"
                {
                    "vulns": [
                        {
                            "id": "OSV-2021-123",
                            "summary": "Example vulnerability summary",
                            "details": "Example vulnerability details",
                            "severity": {
                                "score": {
                                    "value": 9.8,
                                    "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "source": {
                                        "name": "",
                                        "url": ""
                                    }
                                }
                            },
                            "affected": {
                                "ranges": [
                                    {
                                        "type": "ECOSYSTEM",
                                        "events": [
                                            {
                                                "introduced": ""
                                            },
                                            {
                                                "fixed": "1.0.1"
                                            }
                                        ]
                                    }
                                ]
                            }
                        }
                    ]
                }
"@
            }
        }
        # Mock response for pkg:npm/example 2@1.4.0
        "pkg:npm/example 2@1.4.0" {
            return [PSCustomObject]@{
                Content = @"
                {
                    "vulns": [
                        {
                            "id": "OSV-2021-123",
                            "summary": "Example vulnerability summary",
                            "details": "Example vulnerability details",
                            "severity": {
                                "score": {
                                    "value": 9.8,
                                    "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "source": {
                                        "name": "",
                                        "url": ""
                                    }
                                }
                            },
                            "affected": {
                                "ranges": [
                                    {
                                        "type": "ECOSYSTEM",
                                        "events": [
                                            {
                                                "introduced": ""
                                            },
                                            {
                                                "fixed": "1.0.1"
                                            }
                                        ]
                                    }
                                ]
                            }
                        },
                        {
                            "id": "OSV-2021-123-2nd",
                            "summary": "Example 2 vulnerability summary",
                            "details": "Example 2 vulnerability details",
                            "severity": {
                                "score": {
                                    "value": 9.8,
                                    "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "source": {
                                        "name": "",
                                        "url": ""
                                    }
                                }
                            },
                            "affected": {
                                "ranges": [
                                    {
                                        "type": "ECOSYSTEM",
                                        "events": [
                                            {
                                                "introduced": ""
                                            },
                                            {
                                                "fixed": "1.4.1"
                                            }
                                        ]
                                    }
                                ]
                            }
                        }
                    ]
                }
"@
            }
        }
        # Mock response for any other purl
        default {
            return [PSCustomObject]@{
                Content = @"
                {
                    "vulns": []
                }
"@
            }
        }
    }
}

# Run the tests for Get-VulnList
Describe 'Get-VulnList' {
    BeforeAll {
        # Replace Invoke-WebRequest with the mock function
        Mock Invoke-WebRequest -Verifiable -MockWith { Mock-InvokeWebRequest @args }
    }

    It 'writes <ExpectedOutput> to <outfile> when SBOM is <SBOM> and ListAll is <ListAll>' -TestCases $testCases {
        param($SBOM, $outfile, $ListAll, $ExpectedOutput)

        # Remove the output file if it exists
        if (Test-Path $outfile) {
            Remove-Item $outfile
        }

        # Invoke the function with the test parameters
        Get-VulnList -SBOM $SBOM -outfile $outfile -ListAll $ListAll

        # Check if the output file exists and contains the expected output
        Test-Path $outfile | Should -BeTrue
        Get-Content $outfile | Should -BeExactly $ExpectedOutput

        # Remove the output file
        Remove-Item $outfile
    }
}
