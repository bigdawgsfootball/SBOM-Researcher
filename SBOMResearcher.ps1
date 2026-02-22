function Convert-CVSS3StringToBaseScore {
    # This function takes a CVSS v3.1 string as input and returns the base score as output
    param (
        [Parameter(Mandatory=$true)]
        [string]$CVSSString # The CVSS v3.1 string to convert
    )

    # Validate the input string
    if ($CVSSString -notmatch "CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]") {
        throw "Invalid CVSS v3.x string format"
        return
    }

    # Split the string into metrics and values
    $values = $CVSSString.Split("/")[1..8] | ForEach-Object {$_.Split(":")[1]}

    # Define the weight tables for each metric
    $AVWeights = @{
        N = 0.85
        A = 0.62
        L = 0.55
        P = 0.2
    }

    $ACWeights = @{
        L = 0.77
        H = 0.44
    }

    $PRWeights = @{
        N = @{
            U = 0.85
            C = 0.85
        }
        L = @{
            U = 0.62
            C = 0.68
        }
        H = @{
            U = 0.27
            C = 0.5
        }
    }

    $UIWeights = @{
        N = 0.85
        R = 0.62
    }

    $CWeights = @{
        N = 0
        L = 0.22
        H = 0.56
    }

    $IWeights = @{
        N = 0
        L = 0.22
        H = 0.56
    }

    $AWeights = @{
        N = 0
        L = 0.22
        H = 0.56
    }

    # Calculate the impact sub-score using the formula from the CVSS specification
    $ISSBase = 1 - ((1 - $CWeights[$values[5]]) * (1 - $IWeights[$values[6]]) * (1 - $AWeights[$values[7]]))

    # Adjust the impact sub-score based on the scope metric value using the formula from the CVSS specification
    if ($values[4] -eq "U") {
        $ISSFinal = 6.42 * $ISSBase
    } else {
        $ISSFinal = 7.52 * ($ISSBase - 0.029) - 15 * [Math]::Pow(($ISSBase - 0.02),15)
    }

    # Calculate the exploitability sub-score using the formula from the CVSS specification
    $ESSFinal = 8.22 * $AVWeights[$values[0]] * $ACWeights[$values[1]] * $prweights[$values[2]][$values[4]] * $UIWeights[$values[3]]

    # Calculate the base score using the formula from the CVSS specification
    if ($ISSFinal -le 0) {
        $BaseScoreFinal = 0
    }
    elseif ($values[4] -eq "U") {
        $BaseScoreFinal = [math]::Min([math]::Round(($ISSFinal + $ESSFinal),1),10)
    }
    else {
        $BaseScoreFinal = [math]::Min([math]::Round((($ISSFinal + $ESSFinal) * 1.08),1),10)
    }

    # Return the base score as output
    return $BaseScoreFinal
}

function Convert-CVSS4StringToBaseScore {
<#
.SYNOPSIS
    Calculates a CVSS v4.0 score from a vector string.

.DESCRIPTION
    Parses a CVSS v4.0 vector string and computes the numeric score and severity rating.
    Algorithm and data structures are a direct translation of the official reference
    implementation at https://github.com/FIRSTdotorg/cvss-v4-calculator (which is a fork
    of https://github.com/RedHatProductSecurity/cvss-v4-calculator).

.PARAMETER Vector
    A CVSS v4.0 vector string, e.g.:
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"

.EXAMPLE
    .\CVSSv4Calc.ps1 "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
    Score: 10.0  Severity: Critical  MacroVector: 000000

.NOTES
    Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors
    Licensed under BSD-2-Clause. PowerShell translation by Claude.
#>

param(
    [Parameter(Mandatory = $false, Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Vectors
)

# ---------------------------------------------------------------------------
# Lookup Tables (translated directly from constants4.py / cvss_lookup.js)
# ---------------------------------------------------------------------------

# MacroVector score table (270 entries)
$CVSS_LOOKUP_GLOBAL = @{
    "000000" = 10;   "000001" = 9.9;  "000010" = 9.8;  "000011" = 9.5;
    "000020" = 9.5;  "000021" = 9.2;  "000100" = 10;   "000101" = 9.6;
    "000110" = 9.3;  "000111" = 8.7;  "000120" = 9.1;  "000121" = 8.1;
    "000200" = 9.3;  "000201" = 9.0;  "000210" = 8.9;  "000211" = 8.0;
    "000220" = 8.1;  "000221" = 6.8;  "001000" = 9.8;  "001001" = 9.5;
    "001010" = 9.5;  "001011" = 9.2;  "001020" = 9.0;  "001021" = 8.4;
    "001100" = 9.3;  "001101" = 9.2;  "001110" = 8.9;  "001111" = 8.1;
    "001120" = 8.1;  "001121" = 6.5;  "001200" = 8.8;  "001201" = 8.0;
    "001210" = 7.8;  "001211" = 7.0;  "001220" = 6.9;  "001221" = 4.8;
    "002001" = 9.2;  "002011" = 8.2;  "002021" = 7.2;  "002101" = 7.9;
    "002111" = 6.9;  "002121" = 5.0;  "002201" = 6.9;  "002211" = 5.5;
    "002221" = 2.7;  "010000" = 9.9;  "010001" = 9.7;  "010010" = 9.5;
    "010011" = 9.2;  "010020" = 9.2;  "010021" = 8.5;  "010100" = 9.5;
    "010101" = 9.1;  "010110" = 9.0;  "010111" = 8.3;  "010120" = 8.4;
    "010121" = 7.1;  "010200" = 9.2;  "010201" = 8.1;  "010210" = 8.2;
    "010211" = 7.1;  "010220" = 7.2;  "010221" = 5.3;  "011000" = 9.5;
    "011001" = 9.3;  "011010" = 9.2;  "011011" = 8.5;  "011020" = 8.5;
    "011021" = 7.3;  "011100" = 9.2;  "011101" = 8.2;  "011110" = 8.0;
    "011111" = 7.2;  "011120" = 7.0;  "011121" = 5.9;  "011200" = 8.4;
    "011201" = 7.0;  "011210" = 7.1;  "011211" = 5.2;  "011220" = 5.0;
    "011221" = 3.0;  "012001" = 8.6;  "012011" = 7.5;  "012021" = 5.2;
    "012101" = 7.1;  "012111" = 5.2;  "012121" = 2.9;  "012201" = 6.3;
    "012211" = 2.9;  "012221" = 1.7;  "100000" = 9.8;  "100001" = 9.5;
    "100010" = 9.4;  "100011" = 8.7;  "100020" = 9.1;  "100021" = 8.1;
    "100100" = 9.4;  "100101" = 8.9;  "100110" = 8.6;  "100111" = 7.4;
    "100120" = 7.7;  "100121" = 6.4;  "100200" = 8.7;  "100201" = 7.5;
    "100210" = 7.4;  "100211" = 6.3;  "100220" = 6.3;  "100221" = 4.9;
    "101000" = 9.4;  "101001" = 8.9;  "101010" = 8.8;  "101011" = 7.7;
    "101020" = 7.6;  "101021" = 6.7;  "101100" = 8.6;  "101101" = 7.6;
    "101110" = 7.4;  "101111" = 5.8;  "101120" = 5.9;  "101121" = 5.0;
    "101200" = 7.2;  "101201" = 5.7;  "101210" = 5.7;  "101211" = 5.2;
    "101220" = 5.2;  "101221" = 2.5;  "102001" = 8.3;  "102011" = 7.0;
    "102021" = 5.4;  "102101" = 6.5;  "102111" = 5.8;  "102121" = 2.6;
    "102201" = 5.3;  "102211" = 2.1;  "102221" = 1.3;  "110000" = 9.5;
    "110001" = 9.0;  "110010" = 8.8;  "110011" = 7.6;  "110020" = 7.6;
    "110021" = 7.0;  "110100" = 9.0;  "110101" = 7.7;  "110110" = 7.5;
    "110111" = 6.2;  "110120" = 6.1;  "110121" = 5.3;  "110200" = 7.7;
    "110201" = 6.6;  "110210" = 6.8;  "110211" = 5.9;  "110220" = 5.2;
    "110221" = 3.0;  "111000" = 8.9;  "111001" = 7.8;  "111010" = 7.6;
    "111011" = 6.7;  "111020" = 6.2;  "111021" = 5.8;  "111100" = 7.4;
    "111101" = 5.9;  "111110" = 5.7;  "111111" = 5.7;  "111120" = 4.7;
    "111121" = 2.3;  "111200" = 6.1;  "111201" = 5.2;  "111210" = 5.7;
    "111211" = 2.9;  "111220" = 2.4;  "111221" = 1.6;  "112001" = 7.1;
    "112011" = 5.9;  "112021" = 3.0;  "112101" = 5.8;  "112111" = 2.6;
    "112121" = 1.5;  "112201" = 2.3;  "112211" = 1.3;  "112221" = 0.6;
    "200000" = 9.3;  "200001" = 8.7;  "200010" = 8.6;  "200011" = 7.2;
    "200020" = 7.5;  "200021" = 5.8;  "200100" = 8.6;  "200101" = 7.4;
    "200110" = 7.4;  "200111" = 6.1;  "200120" = 5.6;  "200121" = 3.4;
    "200200" = 7.0;  "200201" = 5.4;  "200210" = 5.2;  "200211" = 4.0;
    "200220" = 4.0;  "200221" = 2.2;  "201000" = 8.5;  "201001" = 7.5;
    "201010" = 7.4;  "201011" = 5.5;  "201020" = 6.2;  "201021" = 5.1;
    "201100" = 7.2;  "201101" = 5.7;  "201110" = 5.5;  "201111" = 4.1;
    "201120" = 4.6;  "201121" = 1.9;  "201200" = 5.3;  "201201" = 3.6;
    "201210" = 3.4;  "201211" = 1.9;  "201220" = 1.9;  "201221" = 0.8;
    "202001" = 6.4;  "202011" = 5.1;  "202021" = 2.0;  "202101" = 4.7;
    "202111" = 2.1;  "202121" = 1.1;  "202201" = 2.4;  "202211" = 0.9;
    "202221" = 0.4;  "210000" = 8.8;  "210001" = 7.5;  "210010" = 7.3;
    "210011" = 5.3;  "210020" = 6.0;  "210021" = 5.0;  "210100" = 7.3;
    "210101" = 5.5;  "210110" = 5.9;  "210111" = 4.0;  "210120" = 4.1;
    "210121" = 2.0;  "210200" = 5.4;  "210201" = 4.3;  "210210" = 4.5;
    "210211" = 2.2;  "210220" = 2.0;  "210221" = 1.1;  "211000" = 7.5;
    "211001" = 5.5;  "211010" = 5.8;  "211011" = 4.5;  "211020" = 4.0;
    "211021" = 2.1;  "211100" = 6.1;  "211101" = 5.1;  "211110" = 4.8;
    "211111" = 1.8;  "211120" = 2.0;  "211121" = 0.9;  "211200" = 4.6;
    "211201" = 1.8;  "211210" = 1.7;  "211211" = 0.7;  "211220" = 0.8;
    "211221" = 0.2;  "212001" = 5.3;  "212011" = 2.4;  "212021" = 1.4;
    "212101" = 2.4;  "212111" = 1.2;  "212121" = 0.5;  "212201" = 1.0;
    "212211" = 0.3;  "212221" = 0.1
}

# MAX_COMPOSED: highest-severity vector strings for each EQ level
$MAX_COMPOSED = @{
    "eq1" = @{
        "0" = @("AV:N/PR:N/UI:N/")
        "1" = @("AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/")
        "2" = @("AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/")
    }
    "eq2" = @{
        "0" = @("AC:L/AT:N/")
        "1" = @("AC:H/AT:N/", "AC:L/AT:P/")
    }
    "eq3" = @{
        "0" = @{
            "0" = @("VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/")
            "1" = @("VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/")
        }
        "1" = @{
            "0" = @("VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/")
            "1" = @("VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                    "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                    "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/")
        }
        "2" = @{
            "1" = @("VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/")
        }
    }
    "eq4" = @{
        "0" = @("SC:H/SI:S/SA:S/")
        "1" = @("SC:H/SI:H/SA:H/")
        "2" = @("SC:L/SI:L/SA:L/")
    }
    "eq5" = @{
        "0" = @("E:A/")
        "1" = @("E:P/")
        "2" = @("E:U/")
    }
}

# MAX_SEVERITY: depth of each EQ level (number of steps available)
$MAX_SEVERITY = @{
    "eq1"    = @{ 0 = 1; 1 = 4; 2 = 5 }
    "eq2"    = @{ 0 = 1; 1 = 2 }
    "eq3eq6" = @{
        0 = @{ 0 = 7; 1 = 6 }
        1 = @{ 0 = 8; 1 = 8 }
        2 = @{ 1 = 10 }
    }
    "eq4"    = @{ 0 = 6; 1 = 5; 2 = 4 }
    "eq5"    = @{ 0 = 1; 1 = 1; 2 = 1 }
}

# Metric level values for severity-distance calculation
$AV_Levels = @{ "N" = 0.0; "A" = 0.1; "L" = 0.2; "P" = 0.3 }
$PR_Levels = @{ "N" = 0.0; "L" = 0.1; "H" = 0.2 }
$UI_Levels = @{ "N" = 0.0; "P" = 0.1; "A" = 0.2 }
$AC_Levels = @{ "L" = 0.0; "H" = 0.1 }
$AT_Levels = @{ "N" = 0.0; "P" = 0.1 }
$VC_Levels = @{ "H" = 0.0; "L" = 0.1; "N" = 0.2 }
$VI_Levels = @{ "H" = 0.0; "L" = 0.1; "N" = 0.2 }
$VA_Levels = @{ "H" = 0.0; "L" = 0.1; "N" = 0.2 }
$SC_Levels = @{ "H" = 0.1; "L" = 0.2; "N" = 0.3 }
$SI_Levels = @{ "S" = 0.0; "H" = 0.1; "L" = 0.2; "N" = 0.3 }
$SA_Levels = @{ "S" = 0.0; "H" = 0.1; "L" = 0.2; "N" = 0.3 }
$CR_Levels = @{ "H" = 0.0; "M" = 0.1; "L" = 0.2 }
$IR_Levels = @{ "H" = 0.0; "M" = 0.1; "L" = 0.2 }
$AR_Levels = @{ "H" = 0.0; "M" = 0.1; "L" = 0.2 }

# Valid values per metric
$VALID_VALUES = @{
    "AV"  = "N","A","L","P"
    "AC"  = "L","H"
    "AT"  = "N","P"
    "PR"  = "N","L","H"
    "UI"  = "N","P","A"
    "VC"  = "H","L","N"
    "VI"  = "H","L","N"
    "VA"  = "H","L","N"
    "SC"  = "H","L","N"
    "SI"  = "H","L","N","S"
    "SA"  = "H","L","N","S"
    "E"   = "X","A","P","U"
    "CR"  = "X","H","M","L"
    "IR"  = "X","H","M","L"
    "AR"  = "X","H","M","L"
    "MAV" = "X","N","A","L","P"
    "MAC" = "X","L","H"
    "MAT" = "X","N","P"
    "MPR" = "X","N","L","H"
    "MUI" = "X","N","P","A"
    "MVC" = "X","H","L","N"
    "MVI" = "X","H","L","N"
    "MVA" = "X","H","L","N"
    "MSC" = "X","H","L","N"
    "MSI" = "X","S","H","L","N"
    "MSA" = "X","S","H","L","N"
    "S"   = "X","N","P"
    "AU"  = "X","N","Y"
    "R"   = "X","A","U","I"
    "V"   = "X","D","C"
    "RE"  = "X","L","M","H"
    "U"   = "X","Clear","Green","Amber","Red"
}

$MANDATORY_METRICS = "AV","AC","AT","PR","UI","VC","VI","VA","SC","SI","SA"

# ---------------------------------------------------------------------------
# Helper: parse the vector string
# ---------------------------------------------------------------------------
function Parse-Vector {
    param([string]$VectorStr)

    if (-not $VectorStr.StartsWith("CVSS:4.0/")) {
        throw "Invalid CVSS v4.0 vector: must start with 'CVSS:4.0/'"
    }
    $metrics = @{}
    $parts = $VectorStr.Substring(9) -split "/"
    foreach ($part in $parts) {
        if ($part -eq "") { throw "Empty field in vector" }
        $kv = $part -split ":", 2
        if ($kv.Count -ne 2) { throw "Malformed metric '$part'" }
        $k = $kv[0]; $v = $kv[1]
        if ($metrics.ContainsKey($k)) { throw "Duplicate metric '$k'" }
        if (-not $VALID_VALUES.ContainsKey($k)) { throw "Unknown metric '$k'" }
        if ($v -notin $VALID_VALUES[$k]) { throw "Invalid value '$v' for metric '$k'" }
        $metrics[$k] = $v
    }
    foreach ($m in $MANDATORY_METRICS) {
        if (-not $metrics.ContainsKey($m)) { throw "Missing mandatory metric '$m'" }
    }
    return $metrics
}

# ---------------------------------------------------------------------------
# Helper: get effective metric value (applies Modified overrides and defaults)
# Mirrors the m() function in cvss4.py
# ---------------------------------------------------------------------------
function Get-M {
    param([hashtable]$Metrics, [string]$Metric)

    $selected = $Metrics[$Metric]

    if ($Metric -eq "E" -and $selected -eq "X") { return "A" }
    if ($Metric -in "CR","IR","AR" -and $selected -eq "X") { return "H" }

    $modMetric = "M" + $Metric
    if ($Metrics.ContainsKey($modMetric) -and $Metrics[$modMetric] -ne "X") {
        return $Metrics[$modMetric]
    }
    return $selected
}

# ---------------------------------------------------------------------------
# Helper: expand all metrics so optional ones have defaults
# ---------------------------------------------------------------------------
function Expand-Metrics {
    param([hashtable]$Metrics)
    $exp = @{} + $Metrics
    foreach ($abbr in "MAV","MAC","MAT","MPR","MUI","MVC","MVI","MVA","MSC","MSI","MSA") {
        if (-not $exp.ContainsKey($abbr) -or $exp[$abbr] -eq "X") {
            $exp[$abbr] = $exp[$abbr.Substring(1)]
        }
    }
    foreach ($abbr in "S","AU","R","V","RE","U","CR","IR","AR","E") {
        if (-not $exp.ContainsKey($abbr)) { $exp[$abbr] = "X" }
    }
    return $exp
}

# ---------------------------------------------------------------------------
# Helper: extract a metric value from a max-vector fragment like "AV:N/PR:N/"
# ---------------------------------------------------------------------------
function Extract-M {
    param([string]$Frag, [string]$Metric)
    $tag = $Metric + ":"
    $idx = $Frag.IndexOf($tag)
    if ($idx -lt 0) { return $null }
    $rest = $Frag.Substring($idx + $tag.Length)
    $slash = $rest.IndexOf("/")
    if ($slash -ge 0) { return $rest.Substring(0, $slash) } else { return $rest }
}

# ---------------------------------------------------------------------------
# Compute MacroVector string (6 digits EQ1..EQ6)
# ---------------------------------------------------------------------------
function Get-MacroVector {
    param([hashtable]$Metrics)

    $AV = Get-M $Metrics "AV"; $PR = Get-M $Metrics "PR"; $UI = Get-M $Metrics "UI"
    $AC = Get-M $Metrics "AC"; $AT = Get-M $Metrics "AT"
    $VC = Get-M $Metrics "VC"; $VI = Get-M $Metrics "VI"; $VA = Get-M $Metrics "VA"
    $SC = Get-M $Metrics "SC"; $SI = Get-M $Metrics "SI"; $SA = Get-M $Metrics "SA"
    $MSI = Get-M $Metrics "MSI"; $MSA = Get-M $Metrics "MSA"
    $E  = Get-M $Metrics "E"
    $CR = Get-M $Metrics "CR"; $IR = Get-M $Metrics "IR"; $AR = Get-M $Metrics "AR"

    # EQ1
    if ($AV -eq "N" -and $PR -eq "N" -and $UI -eq "N") { $eq1 = "0" }
    elseif ( ($AV -eq "N" -or $PR -eq "N" -or $UI -eq "N") -and
             -not ($AV -eq "N" -and $PR -eq "N" -and $UI -eq "N") -and
             $AV -ne "P" ) { $eq1 = "1" }
    else { $eq1 = "2" }

    # EQ2
    $eq2 = if ($AC -eq "L" -and $AT -eq "N") { "0" } else { "1" }

    # EQ3
    if ($VC -eq "H" -and $VI -eq "H") { $eq3 = "0" }
    elseif (-not ($VC -eq "H" -and $VI -eq "H") -and ($VC -eq "H" -or $VI -eq "H" -or $VA -eq "H")) { $eq3 = "1" }
    else { $eq3 = "2" }

    # EQ4
    if ($MSI -eq "S" -or $MSA -eq "S") { $eq4 = "0" }
    elseif (-not ($MSI -eq "S" -or $MSA -eq "S") -and ($SC -eq "H" -or $SI -eq "H" -or $SA -eq "H")) { $eq4 = "1" }
    else { $eq4 = "2" }

    # EQ5
    $eq5 = switch ($E) { "A" { "0" } "P" { "1" } default { "2" } }

    # EQ6
    $eq6 = if (($CR -eq "H" -and $VC -eq "H") -or ($IR -eq "H" -and $VI -eq "H") -or ($AR -eq "H" -and $VA -eq "H")) { "0" } else { "1" }

    return "$eq1$eq2$eq3$eq4$eq5$eq6"
}

# ---------------------------------------------------------------------------
# Round to 1dp using "round half away from zero"
# ---------------------------------------------------------------------------
function Final-Rounding([double]$x) {
    $eps = 1e-6
    return [math]::Round($x + $eps, 1, [System.MidpointRounding]::AwayFromZero)
}

# ---------------------------------------------------------------------------
# Main scoring algorithm
# ---------------------------------------------------------------------------
function Compute-Score {
    param([hashtable]$Metrics)

    # Score 0 when all impact metrics are None
    $allNone = @("VC","VI","VA","SC","SI","SA") | ForEach-Object { Get-M $Metrics $_ } | Where-Object { $_ -ne "N" }
    if (-not $allNone) { return 0.0 }

    $mv = Get-MacroVector $Metrics
    $value = [double]$CVSS_LOOKUP_GLOBAL[$mv]

    $e1 = [int]"$($mv[0])"; $e2 = [int]"$($mv[1])"; $e3 = [int]"$($mv[2])"
    $e4 = [int]"$($mv[3])"; $e5 = [int]"$($mv[4])"; $e6 = [int]"$($mv[5])"

    # Next-lower MacroVectors for each EQ dimension
    $eq1_next = "$($e1+1)$e2$e3$e4$e5$e6"
    $eq2_next = "$e1$($e2+1)$e3$e4$e5$e6"
    $eq4_next = "$e1$e2$e3$($e4+1)$e5$e6"
    $eq5_next = "$e1$e2$e3$e4$($e5+1)$e6"

    # EQ3+EQ6 combined (special stepping logic)
    $eq3eq6_next = $null; $eq3eq6_next_l = $null; $eq3eq6_next_r = $null
    if     ($e3 -eq 1 -and $e6 -eq 1) { $eq3eq6_next = "$e1$e2$($e3+1)$e4$e5$e6" }
    elseif ($e3 -eq 0 -and $e6 -eq 1) { $eq3eq6_next = "$e1$e2$($e3+1)$e4$e5$e6" }
    elseif ($e3 -eq 1 -and $e6 -eq 0) { $eq3eq6_next = "$e1$e2$e3$e4$e5$($e6+1)" }
    elseif ($e3 -eq 0 -and $e6 -eq 0) {
        $eq3eq6_next_l = "$e1$e2$e3$e4$e5$($e6+1)"
        $eq3eq6_next_r = "$e1$e2$($e3+1)$e4$e5$e6"
    } else { $eq3eq6_next = "$e1$e2$($e3+1)$e4$e5$($e6+1)" }

    $NaN = [double]::NaN
    function LookupOrNaN([string]$key) {
        if ($CVSS_LOOKUP_GLOBAL.ContainsKey($key)) { [double]$CVSS_LOOKUP_GLOBAL[$key] } else { $NaN }
    }

    $s_eq1    = LookupOrNaN $eq1_next
    $s_eq2    = LookupOrNaN $eq2_next
    $s_eq4    = LookupOrNaN $eq4_next
    $s_eq5    = LookupOrNaN $eq5_next
    $s_eq3eq6 = if ($null -ne $eq3eq6_next_l) {
        $sl = LookupOrNaN $eq3eq6_next_l; $sr = LookupOrNaN $eq3eq6_next_r
        if ([double]::IsNaN($sl) -and [double]::IsNaN($sr)) { $NaN }
        elseif ([double]::IsNaN($sl)) { $sr }
        elseif ([double]::IsNaN($sr)) { $sl }
        else { [math]::Max($sl, $sr) }
    } else { LookupOrNaN $eq3eq6_next }

    # Build all max-vectors for this cell and find the one the current vector falls within
    $eq1m  = $MAX_COMPOSED["eq1"]["$e1"]
    $eq2m  = $MAX_COMPOSED["eq2"]["$e2"]
    $eq3e6 = $MAX_COMPOSED["eq3"]["$e3"]["$e6"]
    $eq4m  = $MAX_COMPOSED["eq4"]["$e4"]
    $eq5m  = $MAX_COMPOSED["eq5"]["$e5"]

    $maxVecs = foreach ($a in $eq1m) { foreach ($b in $eq2m) { foreach ($c in $eq3e6) {
        foreach ($d in $eq4m) { foreach ($f in $eq5m) { $a + $b + $c + $d + $f } } } } }

    $sd = $null
    foreach ($maxVec in $maxVecs) {
        $dAV = $AV_Levels[(Get-M $Metrics "AV")] - $AV_Levels[(Extract-M $maxVec "AV")]
        $dPR = $PR_Levels[(Get-M $Metrics "PR")] - $PR_Levels[(Extract-M $maxVec "PR")]
        $dUI = $UI_Levels[(Get-M $Metrics "UI")] - $UI_Levels[(Extract-M $maxVec "UI")]
        $dAC = $AC_Levels[(Get-M $Metrics "AC")] - $AC_Levels[(Extract-M $maxVec "AC")]
        $dAT = $AT_Levels[(Get-M $Metrics "AT")] - $AT_Levels[(Extract-M $maxVec "AT")]
        $dVC = $VC_Levels[(Get-M $Metrics "VC")] - $VC_Levels[(Extract-M $maxVec "VC")]
        $dVI = $VI_Levels[(Get-M $Metrics "VI")] - $VI_Levels[(Extract-M $maxVec "VI")]
        $dVA = $VA_Levels[(Get-M $Metrics "VA")] - $VA_Levels[(Extract-M $maxVec "VA")]
        $dSC = $SC_Levels[(Get-M $Metrics "SC")] - $SC_Levels[(Extract-M $maxVec "SC")]
        $dSI = $SI_Levels[(Get-M $Metrics "SI")] - $SI_Levels[(Extract-M $maxVec "SI")]
        $dSA = $SA_Levels[(Get-M $Metrics "SA")] - $SA_Levels[(Extract-M $maxVec "SA")]
        $dCR = $CR_Levels[(Get-M $Metrics "CR")] - $CR_Levels[(Extract-M $maxVec "CR")]
        $dIR = $IR_Levels[(Get-M $Metrics "IR")] - $IR_Levels[(Extract-M $maxVec "IR")]
        $dAR = $AR_Levels[(Get-M $Metrics "AR")] - $AR_Levels[(Extract-M $maxVec "AR")]

        if ($dAV -ge 0 -and $dPR -ge 0 -and $dUI -ge 0 -and $dAC -ge 0 -and $dAT -ge 0 -and
            $dVC -ge 0 -and $dVI -ge 0 -and $dVA -ge 0 -and $dSC -ge 0 -and $dSI -ge 0 -and
            $dSA -ge 0 -and $dCR -ge 0 -and $dIR -ge 0 -and $dAR -ge 0) {
            $sd = @{ AV=$dAV; PR=$dPR; UI=$dUI; AC=$dAC; AT=$dAT
                     VC=$dVC; VI=$dVI; VA=$dVA; SC=$dSC; SI=$dSI; SA=$dSA
                     CR=$dCR; IR=$dIR; AR=$dAR }
            break
        }
    }
    if ($null -eq $sd) {
        $sd = @{ AV=0;PR=0;UI=0;AC=0;AT=0;VC=0;VI=0;VA=0;SC=0;SI=0;SA=0;CR=0;IR=0;AR=0 }
    }

    # Aggregate distances per EQ
    $dist_eq1    = $sd.AV + $sd.PR + $sd.UI
    $dist_eq2    = $sd.AC + $sd.AT
    $dist_eq3eq6 = $sd.VC + $sd.VI + $sd.VA + $sd.CR + $sd.IR + $sd.AR
    $dist_eq4    = $sd.SC + $sd.SI + $sd.SA

    $step = 0.1
    $maxsev_eq1    = $MAX_SEVERITY["eq1"][$e1] * $step
    $maxsev_eq2    = $MAX_SEVERITY["eq2"][$e2] * $step
    $maxsev_eq3eq6 = $MAX_SEVERITY["eq3eq6"][$e3][$e6] * $step
    $maxsev_eq4    = $MAX_SEVERITY["eq4"][$e4] * $step

    $avail_eq1    = $value - $s_eq1
    $avail_eq2    = $value - $s_eq2
    $avail_eq3eq6 = $value - $s_eq3eq6
    $avail_eq4    = $value - $s_eq4
    $avail_eq5    = $value - $s_eq5

    $n = 0; $norm1=0.0; $norm2=0.0; $norm3=0.0; $norm4=0.0; $norm5=0.0

    if (-not [double]::IsNaN($avail_eq1)    -and $avail_eq1    -ge 0) { $n++; $norm1 = $avail_eq1    * ($dist_eq1    / $maxsev_eq1)    }
    if (-not [double]::IsNaN($avail_eq2)    -and $avail_eq2    -ge 0) { $n++; $norm2 = $avail_eq2    * ($dist_eq2    / $maxsev_eq2)    }
    if (-not [double]::IsNaN($avail_eq3eq6) -and $avail_eq3eq6 -ge 0) { $n++; $norm3 = $avail_eq3eq6 * ($dist_eq3eq6 / $maxsev_eq3eq6) }
    if (-not [double]::IsNaN($avail_eq4)    -and $avail_eq4    -ge 0) { $n++; $norm4 = $avail_eq4    * ($dist_eq4    / $maxsev_eq4)    }
    if (-not [double]::IsNaN($avail_eq5)    -and $avail_eq5    -ge 0) { $n++; $norm5 = 0.0 }   # eq5 pct always 0

    $mean = if ($n -eq 0) { 0.0 } else { ($norm1 + $norm2 + $norm3 + $norm4 + $norm5) / $n }

    $value -= $mean
    $value = [math]::Max(0.0, [math]::Min(10.0, $value))
    return Final-Rounding $value
}

# ---------------------------------------------------------------------------
# Severity from score
# ---------------------------------------------------------------------------
function Get-Severity([double]$Score) {
    if ($Score -eq 0.0) { "None" }
    elseif ($Score -le 3.9) { "Low" }
    elseif ($Score -le 6.9) { "Medium" }
    elseif ($Score -le 8.9) { "High" }
    else { "Critical" }
}

# ---------------------------------------------------------------------------
# Helper: score one vector string, return a result object (or error row)
# ---------------------------------------------------------------------------
function Invoke-CVSSScore {
    param([string]$Vec)
    try {
        $parsed   = Parse-Vector $Vec
        $expanded = Expand-Metrics $parsed
        $macro    = Get-MacroVector $expanded
        $score    = Compute-Score $expanded
        $severity = Get-Severity $score
        [PSCustomObject]@{
            Score       = ("{0:F1}" -f $score)
            Severity    = $severity
            MacroVector = $macro
            Vector      = $Vec
            Error       = ""
        }
    } catch {
        [PSCustomObject]@{
            Score       = ""
            Severity    = ""
            MacroVector = ""
            Vector      = $Vec
            Error       = "$_"
        }
    }
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if ($Vectors -and $Vectors.Count -gt 0) {
    # ---- One or more vectors passed as arguments ----
    $results = $Vectors | ForEach-Object { Invoke-CVSSScore $_ }

    if ($results.Count -eq 1 -and -not $results[0].Error) {
        $r = $results[0]
        return $r
        #Write-Host ("Score: {0}  Severity: {1}  MacroVector: {2}" -f $r.Score, $r.Severity, $r.MacroVector)
    } else {
        #$results | Format-Table -AutoSize -Property Score, Severity, MacroVector, Vector, Error
        return $results.Score
    }

    # Exit with error code if any rows have errors
    if ($results | Where-Object { $_.Error }) { exit 1 }

} else {
    # ---- Interactive mode ----
    Write-Host "CVSS v4.0 Interactive Calculator  (Ctrl+C or blank input to exit)"
    Write-Host ""
    while ($true) {
        $vecStr = Read-Host "Enter CVSS v4.0 vector"
        if ([string]::IsNullOrWhiteSpace($vecStr)) { break }
        $r = Invoke-CVSSScore $vecStr.Trim()
        if ($r.Error) {
            Write-Host "  Error: $($r.Error)" -ForegroundColor Red
        } else {
            Write-Host ("  Score: {0}  Severity: {1}  MacroVector: {2}" -f $r.Score, $r.Severity, $r.MacroVector)
        }
        Write-Host ""
    }
}
}
function ConvertTo-Version {
    param (
        [Parameter(Mandatory=$true)]
        [string]$VersionString
    )
    # Split the string by dot or any non-digit character
    $parts = $VersionString -split '[\.\D]+'
    # Create a new string with the parts
    return ($parts -join '.')
}

function Get-HighVersion {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true)][string]$High,
        [Parameter(Mandatory=$true)][string]$Compare
    )
    #compares 2 Version objects and returns the 'newer' one
    #-gt doesn't work with empty strings, so need to use "UNSET" to indicate ""
    if ($High -eq "") {
        $High = "UNSET"
    }
    if ($Compare -eq "") {
        $Compare = "UNSET"
    }

    if ($Compare -ne "UNSET") {
        if ($High -eq "UNSET") {
            $High = $Compare
        } elseif ($High -ne "Unresolved version") {
            try {
                #sometimes the version string can't be cast correctly
                if ([System.Version]$Compare -gt [System.Version]$High) {
                    $High = $Compare
                }
            } catch {
                try {
                    $Compare2 = ConvertTo-Version($Compare)
                    if ([System.Version]$Compare2 -gt [System.Version]$High) {
                        $High = $Compare2
                    }
                } catch {
                    $High = "Unresolved version"
                }
            }
        }
    } else {
        $High = "Unresolved version"
    }

    Return $High
}

function PrintLicenses {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][object[]]$alllicenses
    )

    $licstr = ""
    $LowAction = ""
    $MedAction = ""
    $HighAction = ""
    $LowObj = [System.Collections.Generic.List[PSObject]]::new()
    $MedObj = [System.Collections.Generic.List[PSObject]]::new()
    $HighObj = [System.Collections.Generic.List[PSObject]]::new()
    $UnmappedObj = [System.Collections.Generic.List[PSObject]]::new()
    $AllObj = [System.Collections.Generic.List[PSObject]]::new()

    #Low Action licenses generally require very little action / attribution to include or modify the code
    $LowActionLicenses = @("GFDL-1.3-or-later", "GFDL-1.3-only", "GFDL-1.2-or-later", "GFDL-1.2-only", "Apache", "Apache 2.0", "GNU", "MIT", "MIT License", "Apache-2.0", "ISC", "BSD", "BSD-4-Clause", "BSD-3", "BSD-3-Clause", "BSD-2-Clause", "BSD-1-Clause", "BSD-4-Clause-UC", "Unlicense", "Zlib", "Libpng", "Wtfpl-2.0", "OFL-1.1", "Edl-v10", "CCA-4.0", "0BSD", "CC0", "CC0-1.0", "BSD-2-Clause-NetBSD", "Beerware", "PostgreSQL", "OpenSSL", "W3C", "HPND", "curl", "NTP", "WTFPL")
    #Medium Action licenses require some action in order to use or modify the code in a deritive work
    $MedActionLicenses = @("IPL-1.0", "EPL-2.0", "MPL-1.0", "MPL-1.1", "MPL-2.0", "EPL-1.0", "CDDL-1.1", "AFL-2.1", "CPL-1.0", "CC-BY-4.0", "Artistic", "Artistic-2.0", "CC-BY-3.0", "AFL-3.0", "BSL-1.0", "OLDAP-2.8", "Python-2.0", "Ruby", "X11", "PSF-2.0", "Python", "Python Software Foundation License")
    #High Action licenses often require actions that we may not be able to take, like applying a copyright on the deritive work (which gov't produced code can't do) or applying the same license to the deritive work (which gov't produced code is licensed differently)
    $HighActionLicenses = @("AGPL-3.0-or-later", "AGPL-3.0-only", "GPL-1.0-or-later", "GPL-3.0-only", "GPL-1.0-only", "LGPL-2.1-only", "LGPL-2.0-only", "LGPL-3.0-only", "GPL", "LGPL", "LGPL-2.0-or-later", "LGPL-2.1-or-later", "GPL-2.0-or-later", "GPL-2.0-only", "GPL-3.0-or-later", "GPL-2.0+", "GPLv2+", "GPL-2.1+", "GPL-3.0+", "LGPL-2.0", "LGPL-2.0+", "LGPL-2.1", "LGPL-2.1+", "LGPL-3.0", "LGPL-3.0+", "GPL-2.0", "CC-BY-3.0-US", "CC-BY-SA-3.0", "GFDL-1.2", "GFDL-1.3", "GPL-3.0", "GPL-1.0", "GPL-1.0+", "IJG", "AGPL-3.0", "CC-BY-SA-4.0")

    #determine all the license Action categories
    foreach ($lic in $alllicenses) {
        if (($LowActionLicenses.Contains($lic)) -and ($lic -notin $LowAction)) {
            $LowAction += $lic + "   "
            $element = @{
                License = $lic
                Type = "LOW"
            }
            $LowObj.add($element)
        } elseif (($MedActionLicenses.Contains($lic))-and ($lic -notin $MedAction)) {
            $MedAction += $lic + "   "
            $element = @{
                License = $lic
                Type = "MEDIUM"
            }
            $MedObj.add($element)
        } elseif (($HighActionLicenses.Contains($lic)) -and ($lic -notin $HighAction)){
            $HighAction += $lic + "   "
            $element = @{
                License = $lic
                Type = "HIGH"
            }
            $HighObj.add($element)
        } else {
            if ( -not($licstr.Contains($lic))) {
            $licstr += $lic + "   "
                $element = @{
                    License = $lic
                    Type = "UNMAPPED"
                }
                $UnmappedObj.add($element)
            }
        }
    }

    #Print out all unique licenses found in the SBOM
    Write-Output "------------------------------------------------------------" | Out-File -FilePath $outfile -Append
    Write-Output "-   Low Action Licenses found in this SBOM:  $LowAction" | Out-File -FilePath $outfile -Append
    Write-Output "-   Medium Action Licenses found in this SBOM:  $MedAction" | Out-File -FilePath $outfile -Append
    Write-Output "-   High Action Licenses found in this SBOM:  $HighAction" | Out-File -FilePath $outfile -Append
    Write-Output "-   Unmapped Licenses found in this SBOM:  $licstr" | Out-File -FilePath $outfile -Append
    Write-Output "------------------------------------------------------------" | Out-File -FilePath $outfile -Append

    #now output the JSON Objects
    $licenseFile = "$wrkDir\$($ProjectName)_license.json"
    $AllObj = @{ "Unmapped" = $UnmappedObj; "High" = $HighObj; "Medium" = $MedObj; "Low" = $LowObj } | ConvertTo-Json -Depth 2
    $AllObj | Out-File -FilePath $licensefile
}

function PrintVulnerabilities {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][object[]]$allcomponents,
        [Parameter(Mandatory=$true)][object[]]$componentLocations
    )

    foreach($component in $allcomponents) {
        if (($null -ne $component.vulns) -and ($component.vulns.count -gt 0)) {
            # Print the component name and version
            Write-Output "------------------------------------------------------------" | Out-File -FilePath $outfile -Append
            Write-Output "-   Component: $($component.name) $($component.version)" | Out-File -FilePath $outfile -Append
            Write-Output "------------------------------------------------------------" | Out-File -FilePath $outfile -Append
            Write-Output "License info:  $($component.license)" | Out-File -FilePath $outfile -Append
            Write-Output "" | Out-File -FilePath $outfile -Append


            foreach ($vuln in $component.Vulns) {
                # Print the vulnerability details
                # some vulnerabilities do not return a summary or fixed version
                Write-Output "Vulnerability: $($vuln.ID)" | Out-File -FilePath $outfile -Append
                Write-Output "Source: $($vuln.Source)" | Out-File -FilePath $outfile -Append
                if ($null -ne $($vuln.Summary)) {
                    Write-Output "Summary: $($vuln.Summary)" | Out-File -FilePath $outfile -Append
                }
                Write-Output "Details:  $($vuln.Details)" | Out-File -FilePath $outfile -Append
                Write-Output "Fixed Version:  $($vuln.Fixed)" | Out-File -FilePath $outfile -Append
                if ($vuln.ScoreURI -ne "") {
                    Write-Output "Score page:  $($vuln.ScoreURI)" | Out-File -FilePath $outfile -Append
                }

                if ($vuln.Score -ne "") {
                    write-output "CVSS Breakdown:               $($vuln.Score)" | Out-File -FilePath $outfile -Append
                    write-output "CVSS Attack Vector:           $($vuln.AV)" | Out-File -FilePath $outfile -Append
                    write-output "CVSS Attack Complexity:       $($vuln.AC)" | Out-File -FilePath $outfile -Append
                    write-output "CVSS Privileges Required:     $($vuln.PR)" | Out-File -FilePath $outfile -Append
                    write-output "CVSS User Interaction:        $($vuln.UI)" | Out-File -FilePath $outfile -Append
                    write-output "CVSS Scope:                   $($vuln.S)" | Out-File -FilePath $outfile -Append
                    write-output "CVSS Confidentiality Impact:  $($vuln.C)" | Out-File -FilePath $outfile -Append
                    write-output "CVSS Integrity Impact:        $($vuln.I)" | Out-File -FilePath $outfile -Append
                    write-output "CVSS Availability Impact:     $($vuln.A)" | Out-File -FilePath $outfile -Append
                    write-output "CVSS Severity:                $($vuln.Severity)" | Out-File -FilePath $outfile -Append
                } else {
                    write-output "CVSS Breakdown:               CVSS score currently UNASSESSED" | Out-File -FilePath $outfile -Append
                }

                Write-Output "" | Out-File -FilePath $outfile -Append
            }

            #In case the last package has multiple fixed versions, print the high water mark for fixed versions after all have been evaluated
            if ($component.Recommendation -ne "UNSET") {
                Write-Output "##############" | Out-File -FilePath $outfile -Append
                Write-Output "-   Recommended Version to upgrade to that addresses all $($component.name) $($component.version) vulnerabilities: $($component.Recommendation)" | Out-File -FilePath $outfile -Append
                Write-Output "##############" | Out-File -FilePath $outfile -Append
            }
        }
    }

    # Now print out all components with vulnerabilities and where they were found
    Write-Output "=========================================================" | Out-File -FilePath $outfile -Append
    write-output "= List of all components with vulnerabilities and their SBOM file" | Out-File -FilePath $outfile -Append
    Write-Output "=========================================================" | Out-File -FilePath $outfile -Append
    Write-Output $componentLocations | Sort-Object -Property component, version | Format-Table | Out-File -FilePath $outfile -Append

    #now output the JSON Objects
    $vulnFile = "$wrkDir\$($ProjectName)_vulns.json"
    $locFile = "$wrkDir\$($ProjectName)_locs.json"
    $allcomponents | ConvertTo-Json -Depth 10 | Out-File -FilePath $vulnfile
    $componentLocations | ConvertTo-Json -Depth 2 | Out-File -FilePath $locFile

}

function Test-PurlFormat {
    param (
        [string]$purl
    )

    #$purlRegex = '^pkg:[a-z]+/[a-zA-Z0-9._-]+@[0-9]+\.[0-9]+\.[0-9]+$'
    $purlDecoded = [System.Web.HttpUtility]::UrlDecode($purl)

    $purlRegex = '^pkg:[a-z0-9-]+/([a-zA-Z0-9._~-]+/?)+@([v0-9]+\.(\*|[0-9]+)\.(\*|[0-9]+)([+-][a-zA-Z0-9._-]+)?)$'

    if ($purlDecoded -match $purlRegex) {
        return $true
    } else {
        return $false
    }   
}

function Get-VersionFromPurl {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory=$true)][string]$purl
    )

    if ($purl -like "*@*") {
        $parts = $purl.Split("@")
        if ($parts[1].contains("?")) {
            $pieces = $parts[1].split("?")
            return $pieces[0]
        } else {
        return $parts[1]
        }
    } else {
        return ""
    }
}

function Get-NameFromPurl {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory=$true)][string]$purl
    )

    if ($purl -like "*@*") {
        $parts = $purl.Split("@")
        $pieces = $parts[0].split("/")
        $name = $pieces.Count - 1
        return $pieces[$name]
    } else {
        return ""
    }
}

function Get-VulnList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][PSObject]$purls,
        [Parameter(Mandatory=$true)][string]$outfile,
        [Parameter(Mandatory=$true)][boolean]$ListAll,
        [Parameter(Mandatory=$true)][decimal]$minScore,
        [Parameter(Mandatory=$true)][ref]$componentLocations,
        [Parameter(Mandatory=$true)][ref]$vulnLocations
    )
    # this function reads through a list of purls and queries the OSV DB using the purl of each component to find all vulnerabilities per component.
    # for each vulnerability, it will collect the summary, deatils, vuln id, fixed version, link to CVSS score calculator, and license info
    # at the end of the component, as well as the recommended upgrade version if all vulnerabilities have been addressed in upgrades

    $index = 0
    $validVuln = 0
    foreach ($purl in $purls) {
        $fixedHigh = "UNSET"

        $index++
        if ($null -ne $purls.count) {
        Write-Progress -Activity "Querying OSV for all purls" -Status "$index of $($purls.count) processed" -PercentComplete (($index / $purls.count) * 100)
        } else {
            Write-Progress -Activity "Querying OSV for all purls" -Status "$index of 1 processed" -PercentComplete (100)
        }

        # Build the JSON body for the OSV API query
        # noticed that OSV.dev records cargo package type as crates.io, need to handle that here on query
        try {
                $body = @{
                    "package" = @{
                        "purl" = $purl.purl.replace(":cargo/",":crates.io/")
                    }
                } | ConvertTo-Json
            } catch {
                write-output "Error constructing OSV.dev query body from purl $($purl) at index $($index): $($_.Exception.Message)"
            }

        # Invoke the OSV API with the JSON body and save the response
        try {
            $response = Invoke-WebRequest -uri "https://api.osv.dev/v1/query" -Method POST -Body $body -UseBasicParsing -ContentType 'application/json'
        } catch {
            Write-Output "OSV search for $($purl.purl) returned an error: $($_.Exception.Message)"
        }

        # Check if the response has any vulnerabilities
        if ($response.Content.length -gt 2) {
            $name = Get-NameFromPurl($purl.purl)
            $version = Get-VersionFromPurl($purl.purl)

            # build new object to store all properties
            $component = [PSCustomObject]@{
                Name = $name
                Version = $version
                Recommendation = ""
                License = $purl.license
                Vulns = [System.Collections.ArrayList]@()
            }

            $vulns = $response.Content | ConvertFrom-Json

            # Loop through each vulnerability in the response
            foreach ($vulnerability in $vulns.vulns) {

                # build new object to store all properties
                $vuln = [PSCustomObject]@{
                    ID = $vulnerability.id
                    Summary = $vulnerability.summary
                    Details = $vulnerability.details
                    Source = "OSV"
                    Fixed = ""
                    Score = ""
                    AV = ""
                    AC = ""
                    PR = ""
                    UI = ""
                    S = ""
                    C = ""
                    I = ""
                    A = ""
                    ScoreURI = ""
                    Severity = ""
                }

                #build uri string to display calculated score and impacted areas
                if ($vulnerability | Get-Member "Severity") {
                    $vuln.Score = $vulnerability.severity[0].score
                    $vuln.AV = $vulnerability.severity[0].score.split("/")[1].split(":")[1]
                    $vuln.AC = $vulnerability.severity[0].score.split("/")[2].split(":")[1]
                    $vuln.PR = $vulnerability.severity[0].score.split("/")[3].split(":")[1]
                    $vuln.UI = $vulnerability.severity[0].score.split("/")[4].split(":")[1]
                    $vuln.S = $vulnerability.severity[0].score.split("/")[5].split(":")[1]
                    $vuln.C = $vulnerability.severity[0].score.split("/")[6].split(":")[1]
                    $vuln.I = $vulnerability.severity[0].score.split("/")[7].split(":")[1]
                    $vuln.A = $vulnerability.severity[0].score.split("/")[8].split(":")[1]

                     $CVSSCount = $vulnerability.severity.score.count
                        if ($CVSSCount -gt 1) {
                            $CVSSSevScore = $vulnerability.severity.score[0]
                        } else {
                            $CVSSSevScore = $vulnerability.severity.score
                        }

                        if ($CVSSSevScore.contains("3.0")) {
                            #CVSS 3.0
                            $scoreuri = "https://www.first.org/cvss/calculator/3.0#"
                            $vuln.ScoreURI = $scoreuri + $CVSSSevScore
                            try {
                                $vuln.Score = Convert-CVSS3StringToBaseScore $CVSSSevScore
                            } catch {
                            Write-Output "$_ for $vulnerability" | Out-File -FilePath $outfile -Append
                        }

                        switch ($vuln.Score)
                        {
                            { $_ -ge 9.0 }  { $vuln.Severity = "CRITICAL"; Break }
                            { ($_ -ge 7.0) -and ($_ -lt 9.0) } { $vuln.Severity = "HIGH"; Break }
                            { ($_ -ge 4.0) -and ($_ -lt 7.0) } { $vuln.Severity = "MEDIUM"; Break }
                            { ($_ -lt 4.0) } { $vuln.Severity = "LOW"; Break }
                            default { $vuln.Severity - "UNKNOWN"}
                        }
                    } elseif ($CVSSSevScore.contains("3.1")) {
                            #CVSS 3.1
                            $scoreuri = "https://www.first.org/cvss/calculator/3.1#"
                            $vuln.ScoreURI = $scoreuri + $CVSSSevScore
                            try {
                                $vuln.Score = Convert-CVSS3StringToBaseScore $CVSSSevScore
                        } catch {
                            Write-Output "$_ for $vulnerability" | Out-File -FilePath $outfile -Append
                        }

                        switch ($vuln.Score)
                        {
                            { $_ -ge 9.0 }  { $vuln.Severity = "CRITICAL"; Break }
                            { ($_ -ge 7.0) -and ($_ -lt 9.0) } { $vuln.Severity = "HIGH"; Break }
                            { ($_ -ge 4.0) -and ($_ -lt 7.0) } { $vuln.Severity = "MEDIUM"; Break }
                            { ($_ -lt 4.0) } { $vuln.Severity = "LOW"; Break }
                            default { $vuln.Severity - "UNKNOWN"}
                        }
                    } elseif ($CVSSSevScore.contains("4.0")) {
                            #CVSS 4.0
                            $scoreuri = "https://www.first.org/cvss/calculator/4.0#"
                            $vuln.ScoreURI = $scoreuri + $CVSSSevScore
                            try {
                                $vuln.Score = Convert-CVSS4StringToBaseScore $CVSSSevScore
                        } catch {
                            Write-Output "$_ for $vulnerability" | Out-File -FilePath $outfile -Append
                        }

                        switch ($vuln.Score)
                        {
                            { $_ -ge 9.0 }  { $vuln.Severity = "CRITICAL"; Break }
                            { ($_ -ge 7.0) -and ($_ -lt 9.0) } { $vuln.Severity = "HIGH"; Break }
                            { ($_ -ge 4.0) -and ($_ -lt 7.0) } { $vuln.Severity = "MEDIUM"; Break }
                            { ($_ -lt 4.0) } { $vuln.Severity = "LOW"; Break }
                            default { $vuln.Severity - "UNKNOWN"}
                        }
                    } else {
                        #if this string shows up in any output file, need to build a new section for the new score version
                        $vuln.ScoreURI = "UPDATE CODE FOR THIS CVSS SCORE TYPE -> $vulnerability.severity.score"
                        $vuln.Severity = "UNKNOWN"
                    }
                }

                #there can be multiple fixed versions, some based on hashes in the repo, you don't want that one
                foreach ($affected in $vulnerability.affected.ranges) {
                    try {
                        if (($affected.type -ne "GIT") -and ($null -ne $affected.events[1].fixed)) {
                            $fixed = $affected.events[1].fixed
                        }
                    } catch {
                        $fixed = "UNSET"
                    }
                }

                if (($fixed -eq "") -or ($null -eq $fixed)) {
                    $fixed = "UNSET"
                }
                $vuln.Fixed = $fixed
                $fixedHigh = Get-HighVersion -High $fixedHigh -Compare $fixed
                $component.Recommendation = $fixedHigh

                if (($null -ne $vuln.score) -and ($vuln.score -ge $minScore)) {
                    $validVuln++
                    Write-Progress -Activity "Number of OSV vulns unassessed or greater than $minScore" -Status ($validVuln) -Id 1
                    $component.Vulns.add($vuln) | Out-Null
                } elseif (($null -eq $vuln.score) -or ($vuln.score -eq "")) {
                    $validVuln++
                    Write-Progress -Activity "Number of OSV vulns unassessed or greater than $minScore" -Status ($validVuln) -Id 1
                    $component.Vulns.add($vuln) | Out-Null
                }
            }

            #we only want to track components with vulnerabilities once, so only add components that we haven't seen yet in the big list
            if ($component.vulns.count -gt 0) {
                if (Compare-Object -Ref $allvulns -Dif $component -Property Name, Version | Where-Object SideIndicator -eq '=>') {
                    $allvulns.Add($component) | Out-Null
                    $loc = [PSCustomObject]@{
                        "component" = $component.name;
                        "version" = $component.version;
                    }
                    foreach ($found in ($componentLocations.value | Where-Object { ($_.component -eq $loc.component) -and ($_.version -eq $loc.version)})) {
                        if (Compare-Object -Ref $vulnLocations.value -Dif $found -Property component, version, file | Where-Object SideIndicator -eq '=>') {
                            $vulnLocations.value.add($found) | Out-Null
                        }
                    }
                } elseif (Compare-Object -Ref $componentLocations -Dif $component -Property component, version, file | Where-Object SideIndicator -eq '=>') { #but we need to know everywhere that component is found so each project can be fixed
                    $loc = [PSCustomObject]@{
                        "component" = $component.name;
                        "version" = $component.version;
                    }
                    foreach ($found in ($componentLocations.value | Where-Object { ($_.component -eq $loc.component) -and ($_.version -eq $loc.version)})) {
                        if (Compare-Object -Ref $vulnLocations.value -Dif $found -Property component, version, file | Where-Object SideIndicator -eq '=>') {
                            $vulnLocations.value.add($found) | Out-Null
                        }
                    }
                }
            }
        } else {
            if ($ListAll) {
                Write-Output "OSV found no vulnerabilities for " $purl.purl | Out-File -FilePath $outfile -Append
            }
        }
    }
}

function Get-SBOMType {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true)][string]$SBOM
    )

    if ($SBOM -like "*CycloneDX*") {
        Return "CycloneDX"
    } elseif ($SBOM -like "*SPDX*") {
        Return "SPDX"
    } else {
        Return "Unsupported"
    }

}

function Get-CycloneDXComponentList {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true)][PSObject]$SBOM,
        [Parameter(Mandatory=$true)][PSObject]$allLicenses,
        [Parameter(Mandatory=$true)][ref]$componentLocations
    )

    $purlList = [System.Collections.Generic.List[PSOBJECT]]::new()

    foreach ($package in $SBOM.components) {
        $type = $package.type
        $pkgLicenses = $package.licenses

        $found = $false
        #Pull out all the unique licenses found in the SBOM as you go. The full list will be printed together in the report.
        foreach ($license in $pkgLicenses) {
            foreach ($complicense in $allLicenses) {
                if ($complicense -eq $license.license.id) {
                    $found = $true
                }
            }
            if (!($found)) {
                if ($null -ne $license.license.id) {
                    $allLicenses += $license.license.id
                }
            }
        }

        if ($type -eq "library" -or $type -eq "framework") {
            # Get the component purl
            if ($package.purl -notin $allpurls) {
                if ($null -ne $license.license.id) {
                    $packageInfo = [PSCustomObject]@{
                        "purl" = $package.purl
                        "license" = $license.license.id
                    }
                } else {
                    $packageInfo = [PSCustomObject]@{
                        "purl" = $package.purl
                        "license" = "NOASSERTION"
                    }
                }

                $purlList.Add($packageInfo)
                $loc = [PSCustomObject]@{
                    "component" = Get-NameFromPurl -purl $package.purl;
                    "version" = Get-VersionFromPurl -purl $package.purl;
                    "file" = $file
                  }
                $componentLocations.value.Add($loc) | Out-Null
            }
        } elseif ($type -eq "operating-system") {
            #OSV does not return good info on Operating Systems, just need to report OS and version for investigation
            $name = $package.name
            $version = $package.version
            $desc = $package.description

            # Print the OS name and version
            Write-Output "------------------------------------------------------------" | Out-File -FilePath $outfile -Append
            Write-Output "-   OS Name:  $name" | Out-File -FilePath $outfile -Append
            Write-Output "-   OS Version: $version" | Out-File -FilePath $outfile -Append
            Write-Output "-   OS Descriptiom:  $desc" | Out-File -FilePath $outfile -Append
            Write-Output "------------------------------------------------------------" | Out-File -FilePath $outfile -Append
        } else {
            #If this pops on the output, need to add code to query OSV for this ecosystem
            Write-Output "Not capturing $type"
        }
    }

    if ($PrintLicenseInfo) {
        Write-Output "------------------------------------------------------------" | Out-File -FilePath $outfile -Append
        Write-Output "-   SBOM File:  $file" | Out-File -FilePath $outfile -Append

        PrintLicenses($allLicenses)
    }

    Return $purlList
}

function Get-SPDXComponentList {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true)][PSObject]$SBOM,
        [Parameter(Mandatory=$true)][PSObject]$allLicenses,
        [Parameter(Mandatory=$true)][ref]$componentLocations
    )

    $purlList = [System.Collections.Generic.List[PSOBJECT]]::new()

    foreach ($package in $SBOM.packages) {
        $decLicense = $package.licenseDeclared
        $conLicense = $package.licenseConcluded
        if (($decLicense -ne "") -and ($null -ne $decLicense)) {
            $useLicense = $decLicense
        } elseif (($conLicense -ne "") -and ($null -ne $conLicense)) {
            $useLicense = $conLicense
        } else {
            $useLicense = "NOASSERTION"
        }

        if (($package.externalRefs.referenceLocator -ne "") -and ($null -ne $package.externalRefs.referenceLocator)) {
            $testVersion = Get-VersionFromPurl -purl $package.externalRefs.referenceLocator
            if ($testVersion -eq "") {
                #$testVersion = ($package.versioninfo).trimstart('^', '>', '<', '=', ' ')
                $rangePattern = '(?<=\>|\>=)\d+(\.\d+){0,2}'
                
                $testVersion = [regex]::Match(($package.versionInfo -replace " ",""), $rangePattern).Value
        }

            if ($testVersion -ne "") {
                $components = $testVersion.Split('.')

                while ($components.count -lt 3) {
                    $testversion += ".0"
                    $components = $testVersion.Split('.')
                }
            }

            $testName = Get-NameFromPurl -purl $package.externalRefs.referenceLocator
            if ($testName -eq "") {
                #encountered some differences in the SPDX purl formats, need to handle those here
                $testName = $package.externalRefs.referenceLocator
                $purlString = $testName + "@" + $testVersion
            } else {
                if (Test-PurlFormat($package.externalRefs.referenceLocator)) {
                    $purlString = ($package.externalRefs.referenceLocator) #.split("@")[0]
                }
            }
        } else {
            $testName = ""
            $testVersion = ""
        }

        $found = $false
        #Pull out all the unique licenses found in the SBOM as you go. The full list will be printed together in the report.
        foreach ($complicense in $allLicenses) {
            if (($complicense -eq $useLicense) -and ($useLicense -ne "NOASSERTION") -and ($null -ne $useLicense)) {
                $found = $true
            }
        }

        if (!($found) -and ($null -ne $useLicense)) {
            $allLicenses += $useLicense
            $found = $true
        } else {
            $found = $false
        }

        foreach ($refType in $package.externalRefs) {
            if ($refType.referenceType -eq "purl") {
                # Get the component purl
                if ($refType.referenceLocator -notin $allpurls) {
                    #$purlList += $refType.referenceLocator
                    if ($found) {
                        $packageInfo = [PSCustomObject]@{
                            "purl" = $purlString
                            "license" = $useLicense
                        }
                } else {
                    $packageInfo = [PSCustomObject]@{
                        "purl" = $purlString
                        "license" = $useLicense
                    }
                }
                    $purlList.Add($packageInfo)

                    $loc = [PSCustomObject]@{
                        "component" = $testName;
                        "version" = $testVersion;
                        "file" = $file
                      }
                    $componentLocations.Value.Add($loc) | Out-Null
                }
            }
        }
    }

    if ($PrintLicenseInfo) {
        Write-Output "------------------------------------------------------------" | Out-File -FilePath $outfile -Append
        Write-Output "-   SBOM File:  $file" | Out-File -FilePath $outfile -Append

        PrintLicenses($allLicenses)
    }

    Return $purlList
}

function SBOMResearcher {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$ProjectName, #Name associated with project, seen in output filenames and official SBOM folder path
        [Parameter(Mandatory=$true)][string]$SBOMPath, #Path to a directory of SBOMs, or path to a single SBOM
        [Parameter(Mandatory=$true)][string]$wrkDir, #Directory where reports will be written, do NOT make it the same as $SBOMPath
        [Parameter(Mandatory=$true)][decimal]$minScore, #minimum score to include in report and output
        [Parameter(Mandatory=$false)][boolean]$ListAll=$false, #flag to write all components found in report, even if no vulnerabilities found
        [Parameter(Mandatory=$false)][boolean]$PrintLicenseInfo=$false #flag to print license info in report
    )

    #Begin main script
    if (get-item $wrkDir) {
       #dir exists
    } else {
        mkdir $wrkDir
    }

    $allLicenses = @()
    $allpurls = @()
    $allVulns=[System.Collections.ArrayList]@()
    $componentLocations=[System.Collections.ArrayList]@()
    $vulnLocations=[System.Collections.ArrayList]@()

    $argType = Get-Item $SBOMPath
    if ($argType.PSIsContainer) {
        #directory
        $outfile = $wrkDir + "\" + $ProjectName + "_report.txt"
        Write-Output "SBOMResearcher Report for Project: $ProjectName" | Out-File -FilePath $outfile
        Write-Output "=====================================================================================" | Out-File -FilePath $outfile -Append
        Write-Output "" | Out-File -FilePath $outfile -Append

        #call Get-Vulns with each file in the directory
        #if files other than sboms are in the directory, this could cause errors
        #that's why it's best not to have the output dir the same as the sbom dir
        foreach ($file in $argtype.GetFiles()) {
            if ($file.extension -eq ".json") {
            $SBOM = Get-Content -Path $file.fullname | ConvertFrom-Json
            $SBOMType = Get-SBOMType -SBOM $SBOM
            switch ($SBOMType) {
                    "CycloneDX" { $allpurls += Get-CycloneDXComponentList -SBOM $SBOM -allLicenses $allLicenses -componentLocations ([ref]$componentLocations) }
                    "SPDX" { $allpurls += Get-SPDXComponentList -SBOM $SBOM -allLicenses $allLicenses -componentLocations ([ref]$componentLocations) }
                "Unsupported" { Write-Output "This SBOM type is not supported" | Out-File -FilePath $outfile -Append }
            }
        }
        }

            if ($null -ne $allpurls) {
            Get-VulnList -purls $allpurls -outfile $outfile -ListAll $ListAll -minScore $minScore -componentLocations ([ref]$componentLocations) -vulnLocations ([ref]$vulnLocations)
            }

            $allVulns | ConvertTo-Json -Depth 5 | Out-Null

        if ($allvulns.Count -gt 0) {
            PrintVulnerabilities -allcomponents $allVulns -componentLocations $vulnLocations
        }
        } else {
            #file
        $outfile = $wrkDir + "\" + $ProjectName + "_report.txt"
        Write-Output "Vulnerabilities found for Project: $ProjectName" | Out-File -FilePath $outfile
            Write-Output "=====================================================================================" | Out-File -FilePath $outfile -Append
            Write-Output "" | Out-File -FilePath $outfile -Append

            $SBOM = Get-Content -Path $SBOMPath | ConvertFrom-Json
            $SBOMType = Get-SBOMType -SBOM $SBOM
            $allpurls = @()
            switch ($SBOMType) {
            "CycloneDX" { $allpurls = Get-CycloneDXComponentList -SBOM $SBOM -allLicenses $allLicenses -componentLocations ([ref]$componentLocations) }
            "SPDX" { $allpurls = Get-SPDXComponentList -SBOM $SBOM -allLicenses $allLicenses -componentLocations ([ref]$componentLocations) }
                "Unsupported" { Write-Output "This SBOM type is not supported" | Out-File -FilePath $outfile -Append }
            }
            if ($null -ne $allpurls) {
            Get-VulnList -purls $allpurls -outfile $outfile -ListAll $ListAll -minScore $minScore -componentLocations ([ref]$componentLocations) -vulnLocations ([ref]$vulnLocations)
            }
            $allVulns | ConvertTo-Json -Depth 5 | Out-Null

        if ($allvulns.Count -gt 0) {
            PrintVulnerabilities -allcomponents $allVulns -componentLocations $vulnLocations
        }
    }
}

SBOMResearcher -SBOMPath "C:\Temp\sbom_test\" -ProjectName "Testing" -wrkDir "C:\Temp\sbom_test\reports" -PrintLicenseInfo $true -minScore 7.0