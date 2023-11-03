BeforeAll {
    # Import the function to test
    . .\SBOMResearcher.ps1
   
    # Mock the Out-File cmdlet to avoid writing to the file system
    $outfile = ".\test.txt"

    # Create an empty array to store the licenses and purls
    $allLicenses = @()
    $allpurls = @()
    
    $PrintLicenseInfo = $true

    # Define some sample input parameters
    $SBOM = [PSCustomObject]@{
        components = @(
            [PSCustomObject]@{
                type = "library"
                name = "Newtonsoft.Json"
                version = "12.0.3"
                purl = "pkg:nuget/Newtonsoft.Json@12.0.3"
                licenses = @(
                    [PSCustomObject]@{
                        license = [PSCustomObject]@{
                            id = "MIT"
                        }
                    }
                )
            },
            [PSCustomObject]@{
                type = "framework"
                name = ".NET Core"
                version = "3.1.0"
                purl = "pkg:nuget/dotnet-core@3.1.0"
                licenses = @(
                    [PSCustomObject]@{
                        license = [PSCustomObject]@{
                            id = "MIT"
                        }
                    }
                )
            },
            [PSCustomObject]@{
                type = "operating-system"
                name = "Windows 10"
                version = "1909"
                description = "Microsoft Windows 10 Home Edition"
            }
        )
    }

    # Define the expected output
    $expectedOutput = @(
        "------------------------------------------------------------",
        "-   OS Name:  Windows 10",
        "-   OS Version: 21H1",
        "-   OS Descriptiom:  The latest version of Windows OS",
        "------------------------------------------------------------"
    )

    $expectedReturn = @("pkg:npm/express@4.17.1")


} #BeforeAll

# Define the test cases
Describe "Get-CycloneDXComponentList" {
    
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
    
    It "should return a list of purls for library and framework components" {
        $allLicenses = @()
        $allpurls = @()

        $result = Get-CycloneDXComponentList -SBOM $SBOM -allLicenses $allLicenses
        $result | Should -Be "pkg:nuget/Newtonsoft.Json@12.0.3pkg:nuget/dotnet-core@3.1.0"
        $? | Should -BeTrue
    }

    It "should write the OS name, version and description to the output file" {
        # Mock the Out-File cmdlet to avoid writing to the file system
        $outfile = ".\test.txt"

        # Set the PrintLicenseInfo switch to false to avoid printing the licenses
        Get-CycloneDXComponentList -SBOM $SBOM -allLicenses $allLicenses
        # Read the content of the output file and compare it with the expected output
        $content = Get-Content -Path $outfile
        $expectedOutput = @(
            "------------------------------------------------------------",
            "-   OS Name:  Windows 10",
            "-   OS Version: 1909",
            "-   OS Descriptiom:  Microsoft Windows 10 Home Edition",
            "------------------------------------------------------------"
        )
        $content | Should -Match $expectedOutput
        $? | Should -BeTrue
    }

}