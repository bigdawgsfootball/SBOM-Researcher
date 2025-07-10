Describe "Convert-CVSS3StringToBaseScore" {
    BeforeAll {
        # Import the module that contains the function to test
        . .\SBOMResearcher.ps1
    }

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
