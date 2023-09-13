BeforeAll {
# Import the function from the script file
. .\SBOMResearcher.ps1

# Define some mock licenses for testing
$mockLowRiskLicense = [PSCustomObject]@{
    license = [PSCustomObject]@{
        id = "MIT"
    }
}

$mockMedRiskLicense = [PSCustomObject]@{
    license = [PSCustomObject]@{
        id = "MPL-2.0"
    }
}

$mockHighRiskLicense = [PSCustomObject]@{
    license = [PSCustomObject]@{
        id = "GPL-3.0"
    }
}

$mockUnmappedLicense = [PSCustomObject]@{
    license = [PSCustomObject]@{
        id = "Unknown"
    }
}

# Define the output file path
$outfile = ".\test.txt"

}



# Start the pester tests
Describe "PrintLicenses" {
    BeforeEach {
        # Remove the output file if it exists
        if ($outfile -and (Test-Path $outfile)) {
            Remove-Item $outfile
        }
    }

    AfterEach {
        # Remove the output file if it exists
        if ($outfile -and (Test-Path $outfile)) {
            Remove-Item $outfile
        }
    }

    It "should print low risk licenses correctly" {
        # Arrange
        $alllicenses = @($mockLowRiskLicense, $mockLowRiskLicense, $mockMedRiskLicense)

        # Act
        PrintLicenses -alllicenses $alllicenses

        # Assert
        $content = Get-Content $outfile -Raw
        $content | Should -Match "-   Low Risk Licenses found in this SBOM:  MIT   MIT"
        $content | Should -Match "-   Medium Risk Licenses found in this SBOM:  MPL-2.0"
        $content | Should -Match "-   High Risk Licenses found in this SBOM:"
        $content | Should -Match "-   Unmapped Licenses found in this SBOM:"
    }

    It "should print medium risk licenses correctly" {
        # Arrange
        $alllicenses = @($mockMedRiskLicense, $mockMedRiskLicense, $mockHighRiskLicense)

        # Act
        PrintLicenses -alllicenses $alllicenses

        # Assert
        $content = Get-Content $outfile -Raw
        $content | Should -Match "-   Medium Risk Licenses found in this SBOM:  MPL-2.0   MPL-2.0"
        $content | Should -Match "-   High Risk Licenses found in this SBOM:  GPL-3.0"
        $content | Should -Match "-   Low Risk Licenses found in this SBOM:"
        $content | Should -Match "-   Unmapped Licenses found in this SBOM:"
    }

    It "should print high risk licenses correctly" {
        # Arrange
        $alllicenses = @($mockHighRiskLicense, $mockHighRiskLicense, $mockUnmappedLicense)

        # Act
        PrintLicenses -alllicenses $alllicenses

        # Assert
        $content = Get-Content $outfile -Raw
        $content | Should -Match "-   High Risk Licenses found in this SBOM:  GPL-3.0   GPL-3.0"
        $content | Should -Match "-   Unmapped Licenses found in this SBOM:  Unknown"
        $content | Should -Match "-   Low Risk Licenses found in this SBOM:"
        $content | Should -Match "-   Medium Risk Licenses found in this SBOM:"
    }

    It "should print unmapped licenses correctly" {
        # Arrange
        $alllicenses = @($mockUnmappedLicense, $mockUnmappedLicense, $mockLowRiskLicense)

        # Act
        PrintLicenses -alllicenses $alllicenses

        # Assert
        $content = Get-Content $outfile -Raw
        $content | Should -Match "-   Unmapped Licenses found in this SBOM:  Unknown   Unknown"
        $content | Should -Match "-   Low Risk Licenses found in this SBOM:  MIT"
        $content | Should -Match "-   Medium Risk Licenses found in this SBOM:"
        $content | Should -Match "-   High Risk Licenses found in this SBOM:"
    }

    It "should throw an error if no licenses are provided" {

       { PrintLicenses -alllicenses $alllicenses } | Should -Throw "Cannot bind argument to parameter 'alllicenses' because it is null."

    }
}
