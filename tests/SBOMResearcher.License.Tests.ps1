# Start the pester tests
Describe "PrintLicenses" {
    BeforeAll {
        # Import the function from the script file
        . .\SBOMResearcher.ps1
    }
    
    # Mocking Out-File to prevent actual file writing during tests
    Mock -CommandName Out-File

    # Test case for Low Action Licenses
    It "Should categorize Low Action Licenses correctly" {
        $alllicenses = @("MIT", "Apache-2.0")
        . PrintLicenses -alllicenses $alllicenses

        # Verify the output
        $LowObj | Should -Contain @{ License = "MIT"; Type = "LOW" }
        $LowObj | Should -Contain @{ License = "Apache-2.0"; Type = "LOW" }
    }

    # Test case for Medium Action Licenses
    It "Should categorize Medium Action Licenses correctly" {
        $alllicenses = @("MPL-2.0", "EPL-1.0")
        . PrintLicenses -alllicenses $alllicenses

        # Verify the output
        $MedObj | Should -Contain @{ License = "MPL-2.0"; Type = "MEDIUM" }
        $MedObj | Should -Contain @{ License = "EPL-1.0"; Type = "MEDIUM" }
    }

    # Test case for High Action Licenses
    It "Should categorize High Action Licenses correctly" {
        $alllicenses = @("GPL-3.0", "AGPL-3.0")
        . PrintLicenses -alllicenses $alllicenses

        # Verify the output
        $HighObj | Should -Contain @{ License = "GPL-3.0"; Type = "HIGH" }
        $HighObj | Should -Contain @{ License = "AGPL-3.0"; Type = "HIGH" }
    }

    # Test case for Unmapped Licenses
    It "Should categorize Unmapped Licenses correctly" {
        $alllicenses = @("Unknown-License")
        . PrintLicenses -alllicenses $alllicenses

        # Verify the output
        $UnmappedObj | Should -Contain @{ License = "Unknown-License"; Type = "UNMAPPED" }
    }

    # Test case for mixed licenses
    It "Should categorize mixed licenses correctly" {
        $alllicenses = @("MIT", "MPL-2.0", "GPL-3.0", "Unknown-License")
        . PrintLicenses -alllicenses $alllicenses

        # Verify the output
        $LowObj | Should -Contain @{ License = "MIT"; Type = "LOW" }
        $MedObj | Should -Contain @{ License = "MPL-2.0"; Type = "MEDIUM" }
        $HighObj | Should -Contain @{ License = "GPL-3.0"; Type = "HIGH" }
        $UnmappedObj | Should -Contain @{ License = "Unknown-License"; Type = "UNMAPPED" }
    }
    
    It "should throw an error if no licenses are provided" {

       { PrintLicenses -alllicenses $alllicenses } | Should -Throw "Cannot bind argument to parameter 'alllicenses' because it is null."

    }
}
