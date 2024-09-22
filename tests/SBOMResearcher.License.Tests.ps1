Describe "PrintLicenses" {
    BeforeAll {
        # Import the function from the script file
        . .\SBOMResearcher.ps1
    }
    
    BeforeEach {
        # Set up necessary variables
        $global:outfile = "test_report.txt"
        $global:wrkDir = "C:\Test"
        $global:ProjectName = "TestProject"
        New-Item -ItemType Directory -Path $wrkDir -Force | Out-Null
    }

    AfterEach {
        # Clean up
        Remove-Item -Path $wrkDir -Recurse -Force
    }

    # Mocking Out-File to prevent actual file writing during tests
    Mock -CommandName Out-File

    # Helper function to convert objects to JSON for comparison
    function ConvertTo-JsonString {
        param ($obj)
        return $obj | ConvertTo-Json -Compress
    }

    # Test case for Low Action Licenses
    It "Should categorize Low Action Licenses correctly" {
        $alllicenses = @("MIT", "Apache-2.0")
        . PrintLicenses -alllicenses $alllicenses

        # Verify the output
        $LowObj | ForEach-Object { ConvertTo-JsonString $_ } | Should -Contain (ConvertTo-JsonString @{ License = "MIT"; Type = "LOW" })
        $LowObj | ForEach-Object { ConvertTo-JsonString $_ } | Should -Contain (ConvertTo-JsonString @{ License = "Apache-2.0"; Type = "LOW" })
    }

    # Test case for Medium Action Licenses
    It "Should categorize Medium Action Licenses correctly" {
        $alllicenses = @("MPL-2.0", "EPL-1.0")
        . PrintLicenses -alllicenses $alllicenses

        # Verify the output
        $MedObj | ForEach-Object { ConvertTo-JsonString $_ } | Should -Contain (ConvertTo-JsonString @{ License = "MPL-2.0"; Type = "MEDIUM" })
        $MedObj | ForEach-Object { ConvertTo-JsonString $_ } | Should -Contain (ConvertTo-JsonString @{ License = "EPL-1.0"; Type = "MEDIUM" })
    }

    # Test case for High Action Licenses
    It "Should categorize High Action Licenses correctly" {
        $alllicenses = @("GPL-3.0", "AGPL-3.0")
        . PrintLicenses -alllicenses $alllicenses

        # Verify the output
        $HighObj | ForEach-Object { ConvertTo-JsonString $_ } | Should -Contain (ConvertTo-JsonString @{ License = "GPL-3.0"; Type = "HIGH" })
        $HighObj | ForEach-Object { ConvertTo-JsonString $_ } | Should -Contain (ConvertTo-JsonString @{ License = "AGPL-3.0"; Type = "HIGH" })
    }

    # Test case for Unmapped Licenses
    It "Should categorize Unmapped Licenses correctly" {
        $alllicenses = @("Unknown-License")
        . PrintLicenses -alllicenses $alllicenses

        # Verify the output
        $UnmappedObj | ForEach-Object { ConvertTo-JsonString $_ } | Should -Contain (ConvertTo-JsonString @{ License = "Unknown-License"; Type = "UNMAPPED" })
    }

    # Test case for mixed licenses
    It "Should categorize mixed licenses correctly" {
        $alllicenses = @("MIT", "MPL-2.0", "GPL-3.0", "Unknown-License")
        . PrintLicenses -alllicenses $alllicenses

        # Verify the output
        $LowObj | ForEach-Object { ConvertTo-JsonString $_ } | Should -Contain (ConvertTo-JsonString @{ License = "MIT"; Type = "LOW" })
        $MedObj | ForEach-Object { ConvertTo-JsonString $_ } | Should -Contain (ConvertTo-JsonString @{ License = "MPL-2.0"; Type = "MEDIUM" })
        $HighObj | ForEach-Object { ConvertTo-JsonString $_ } | Should -Contain (ConvertTo-JsonString @{ License = "GPL-3.0"; Type = "HIGH" })
        $UnmappedObj | ForEach-Object { ConvertTo-JsonString $_ } | Should -Contain (ConvertTo-JsonString @{ License = "Unknown-License"; Type = "UNMAPPED" })
    }
    
    It "should throw an error if no licenses are provided" {
        { PrintLicenses -alllicenses $null } | Should -Throw "Cannot bind argument to parameter 'alllicenses' because it is null."
    }
}
