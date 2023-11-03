Describe "Get-VersionFromPurl" {
    BeforeAll {
        # Import the function to test
        . .\SBOMResearcher.ps1
    }
    
    It "returns the version part of a valid purl" {
        $purl = "pkg:npm/angular/animation@12.0.5"
        $version = Get-VersionFromPurl -purl $purl
        $version | Should -Be "12.0.5"
    }

    It "returns an empty string for an invalid purl" {
        $purl = "pkg:npm/angular/animation"
        $version = Get-VersionFromPurl -purl $purl
        $version | Should -Be ""
    }

    It "throws an error for a null or empty purl" {
        { Get-VersionFromPurl } | Should -Throw
        { Get-VersionFromPurl -purl "" } | Should -Throw
    }
}
