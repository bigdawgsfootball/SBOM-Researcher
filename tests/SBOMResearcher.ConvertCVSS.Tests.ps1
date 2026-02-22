    BeforeAll {
        # Import the module that contains the function to test
        . .\SBOMResearcher.ps1
    }
    Describe "Convert-CVSS3StringToBaseScore" {

    It "returns the correct base score for a CRITICAL severity CVSS v3.1 string" {
        # Arrange
        $CVSSString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        $expectedBaseScore = 9.8

        # Act
        $actualBaseScore = Convert-CVSS3StringToBaseScore -CVSSString $CVSSString

        # Assert
        $actualBaseScore | Should -Be $expectedBaseScore
    }

    It "returns the correct base score for a HIGH severity CVSS v3.1 string" {
        # Arrange
        $CVSSString = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
        $expectedBaseScore = 7.4

        # Act
        $actualBaseScore = Convert-CVSS3StringToBaseScore -CVSSString $CVSSString

        # Assert
        $actualBaseScore | Should -Be $expectedBaseScore
    }

    It "returns the correct base score for a MEDIUM severity CVSS v3.1 string" {
        # Arrange
        $CVSSString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
        $expectedBaseScore = 5.3

        # Act
        $actualBaseScore = Convert-CVSS3StringToBaseScore -CVSSString $CVSSString

        # Assert
        $actualBaseScore | Should -Be $expectedBaseScore
    }

    It "returns the correct base score for a LOW severity CVSS v3.1 string" {
        # Arrange
        $CVSSString = "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
        $expectedBaseScore = 2.3

        # Act
        $actualBaseScore = Convert-CVSS3StringToBaseScore -CVSSString $CVSSString

        # Assert
        $actualBaseScore | Should -Be $expectedBaseScore
    }

    It "throws an error for an invalid CVSS v3.1 string" {
        # Arrange
        $CVSSString = "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" # Invalid CVSS string

        # Act
        $scriptBlock = { Convert-CVSS3StringToBaseScore -CVSSString $CVSSString }

        # Assert
        $scriptBlock | Should -Throw -ExpectedMessage "Invalid CVSS v3.x string format"
    }

}


Describe "Convert-CVSS4StringToBaseScore" {

    It "returns the correct base score for a CRITICAL severity CVSS v4.0 string" {
        # Arrange
        $CVSSString = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        $expectedBaseScore = 9.3

        # Act
        $actualBaseScore = Convert-CVSS4StringToBaseScore -CVSSVector $CVSSString

        # Assert
        $actualBaseScore | Should -Be $expectedBaseScore
    }

    It "returns the correct base score for a HIGH severity CVSS v4.0 string" {
        # Arrange
        $CVSSString = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:L/SI:L/SA:N"
        $expectedBaseScore = 8.8

        # Act
        $actualBaseScore = Convert-CVSS4StringToBaseScore -CVSSVector $CVSSString

        # Assert
        $actualBaseScore | Should -Be $expectedBaseScore
    }

    It "returns the correct base score for a MEDIUM severity CVSS v4.0 string" {
        # Arrange
        $CVSSString = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N"
        $expectedBaseScore = 5.3

        # Act
        $actualBaseScore = Convert-CVSS4StringToBaseScore -CVSSVector $CVSSString

        # Assert
        $actualBaseScore | Should -Be $expectedBaseScore
    }

    It "returns the correct base score for a LOW severity CVSS v4.0 string" {
        # Arrange
        $CVSSString = "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H"
        $expectedBaseScore = 2.4

        # Act
        $actualBaseScore = Convert-CVSS4StringToBaseScore -CVSSVector $CVSSString

        # Assert
        $actualBaseScore | Should -Be $expectedBaseScore
    }

    It "returns the correct base score for additional examples" -TestCases @(
        @{ CVSSString = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"; ExpectedBaseScore = 10.0 }
        @{ CVSSString = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L"; ExpectedBaseScore = 6.9 }
        @{ CVSSString = "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"; ExpectedBaseScore = 8.5 }
        @{ CVSSString = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N"; ExpectedBaseScore = 5.1 }
        @{ CVSSString = "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"; ExpectedBaseScore = 7.0 }
        @{ CVSSString = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"; ExpectedBaseScore = 0.0 }
        @{ CVSSString = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"; ExpectedBaseScore = 7.1 }
    ) {
        $actualBaseScore = Convert-CVSS4StringToBaseScore -CVSSVector $CVSSString
        $actualBaseScore | Should -Be $ExpectedBaseScore
    }

    It "throws an error for an invalid CVSS v4.0 string" {
        # Arrange
        $CVSSString = "CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" # Invalid CVSS string

        # Act
        $scriptBlock = { Convert-CVSS4StringToBaseScore -CVSSVector $CVSSString }

        # Assert
        $scriptBlock | Should -Throw -ExpectedMessage "Invalid CVSS v4.0 string format"
    }

}