Describe "Get-NameFromPurl" {
    BeforeAll {
        # Import the function to test
        . .\SBOMResearcher.ps1
    }
    
    It "returns the name part of a valid purl" {
        $purl = "pkg:npm/angular/animation@12.0.5"
        $name = Get-NameFromPurl -purl $purl
        $name | Should -Be "animation"
    }

    It "returns an empty string for an invalid purl" {
        $purl = "pkg:npm/angular/animation"
        $name = Get-NameFromPurl -purl $purl
        $name | Should -Be ""
    }

    It "throws an error for a null or empty purl" {
        { Get-NameFromPurl } | Should -Throw
        { Get-NameFromPurl -purl "" } | Should -Throw
    }
}
