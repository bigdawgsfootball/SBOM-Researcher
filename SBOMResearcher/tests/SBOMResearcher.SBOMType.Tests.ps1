Describe "Get-SBOMType" {
    BeforeAll {
        # Import the function to test
        . .\SBOMResearcher.ps1
    }
    
    It "returns CycloneDX for a valid CycloneDX SBOM" {
        $SBOM = "<bom xmlns='http://cyclonedx.org/schema/bom/1.3' version='1'>...</bom>"
        $type = Get-SBOMType -SBOM $SBOM
        $type | Should -Be "CycloneDX"
    }

    It "returns SPDX for a valid SPDX SBOM" {
        $SBOM = "SPDXVersion: SPDX-2.2 ..."
        $type = Get-SBOMType -SBOM $SBOM
        $type | Should -Be "SPDX"
    }

    It "returns Unsupported for an invalid or unknown SBOM" {
        $SBOM = "<xml>...</xml>"
        $type = Get-SBOMType -SBOM $SBOM
        $type | Should -Be "Unsupported"
    }

    It "throws an error for a null or empty SBOM" {
        { Get-SBOMType } | Should -Throw
        { Get-SBOMType -SBOM "" } | Should -Throw
    }
}
