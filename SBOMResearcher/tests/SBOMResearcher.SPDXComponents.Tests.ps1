# Define a Pester test script
Describe 'Get-SPDXComponentList' {
    BeforeAll {
        # Import the function to test
        . .\SBOMResearcher.ps1
    }

    BeforeEach {
        # Define a mock SBOM object with some sample data
        $mockSBOM = @{
            packages = @(
                @{
                    licenseDeclared = "MIT"
                    licenseConcluded = "MIT"
                    externalRefs = @(
                        @{
                            referenceType = "purl"
                            referenceLocator = "pkg:npm/express@4.17.1"
                        }
                    )
                },
                @{
                    licenseDeclared = "Apache-2.0"
                    licenseConcluded = "NOASSERTION"
                    externalRefs = @(
                        @{
                            referenceType = "purl"
                            referenceLocator = "pkg:npm/react@17.0.2"
                        }
                    )
                },
                @{
                    licenseDeclared = "NOASSERTION"
                    licenseConcluded = "GPL-3.0-only"
                    externalRefs = @(
                        @{
                            referenceType = "purl"
                            referenceLocator = "pkg:npm/jquery@3.6.0"
                        }
                    )
                }
            )
        }

        # Define a mock allLicenses object as an empty array
        $mockAllLicenses = @()

        # Define the expected output of the function
        $expectedOutput = "pkg:npm/express@4.17.1pkg:npm/react@17.0.2pkg:npm/jquery@3.6.0"

        # Define the expected value of the allLicenses object after the function call
        $expectedAllLicenses = @(
            "MIT",
            "Apache-2.0",
            "GPL-3.0-only"
        )
    }

    It 'Given a valid SBOM and an empty allLicenses array, it returns an array of purls and updates the allLicenses array with unique licenses' {
        # Call the function with the mock objects
        $actualOutput = Get-SPDXComponentList -SBOM $mockSBOM -allLicenses $mockAllLicenses

        # Assert that the output matches the expected output
        $actualOutput | Should -BeExactly $expectedOutput

        # Assert that the allLicenses array is updated with the expected value
        $mockAllLicenses | Should -BeExactly $expectedAllLicenses
    }
}
