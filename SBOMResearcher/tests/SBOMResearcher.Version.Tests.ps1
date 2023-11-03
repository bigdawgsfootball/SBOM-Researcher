BeforeAll {
    # Import the function to test
    . .\SBOMResearcher.ps1
}

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

    It "returns <Expected> when High is <High> and Compare is <Compare>" -ForEach $testCases {
        param($High, $Compare, $Expected)
        Get-HighVersion -High $High -Compare $Compare | Should -Be $Expected
    }
}