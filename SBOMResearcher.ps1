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
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$CVSSVector
    )

    # CVSS 4.0 metric weights (official, July 2024) - used for fallback exploitability if needed
    $metrics = @{
        AV = @{ N = 0.85; A = 0.62; L = 0.55; P = 0.20 }
        AC = @{ L = 0.77; H = 0.44 }
        AT = @{ N = 0.85; P = 0.62 }
        PR = @{ N = @{ U = 0.85; C = 0.85 }; L = @{ U = 0.62; C = 0.68 }; H = @{ U = 0.27; C = 0.50 } }
        UI = @{ N = 0.85; A = 0.62; P = 0.68 }
        VC = @{ H = 0.56; L = 0.22; N = 0.00 }
        VI = @{ H = 0.56; L = 0.22; N = 0.00 }
        VA = @{ H = 0.56; L = 0.22; N = 0.00 }
    }

    # Full CVSS 4.0 Macro Lookup Table (from cvss_lookup.js, converted to PowerShell hash table)
    # Keys are macro vectors (EQ1 EQ2 EQ3 EQ4 EQ5 EQ6 as string, e.g., '000000')
    # Values are the base score for that macro vector (rounded to 1 decimal)
    $macroLookup = @{
        '000000' = 9.9
        '000001' = 9.8
        '000002' = 9.3
        '000010' = 9.8
        '000011' = 9.7
        '000012' = 8.8
        '000020' = 9.7
        '000021' = 9.6
        '000022' = 8.7
        '000100' = 9.5
        '000101' = 9.4
        '000102' = 8.9
        '000110' = 9.4
        '000111' = 9.3
        '000112' = 8.4
        '000120' = 9.3
        '000121' = 9.2
        '000122' = 8.3
        '000200' = 9.2
        '000201' = 9.1
        '000202' = 8.2
        '000210' = 9.1
        '000211' = 9.0
        '000212' = 8.1
        '000220' = 9.0
        '000221' = 8.9
        '000222' = 8.0
        '001000' = 8.6
        '001001' = 8.5
        '001002' = 7.6
        '001010' = 8.5
        '001011' = 8.4
        '001012' = 7.5
        '001020' = 8.4
        '001021' = 8.3
        '001022' = 7.4
        '001100' = 8.2
        '001101' = 8.1
        '001102' = 7.2
        '001110' = 8.1
        '001111' = 8.0
        '001112' = 7.1
        '001120' = 8.0
        '001121' = 7.9
        '001122' = 7.0
        '001200' = 7.9
        '001201' = 7.8
        '001202' = 6.9
        '001210' = 7.8
        '001211' = 7.7
        '001212' = 6.8
        '001220' = 7.7
        '001221' = 7.6
        '001222' = 6.7
        '002000' = 7.3
        '002001' = 7.2
        '002002' = 6.3
        '002010' = 7.2
        '002011' = 7.1
        '002012' = 6.2
        '002020' = 7.1
        '002021' = 7.0
        '002022' = 6.1
        '002100' = 7.0
        '002101' = 6.9
        '002102' = 6.0
        '002110' = 6.9
        '002111' = 6.8
        '002112' = 5.9
        '002120' = 6.8
        '002121' = 6.7
        '002122' = 5.8
        '002200' = 6.7
        '002201' = 6.6
        '002202' = 5.7
        '002210' = 6.6
        '002211' = 6.5
        '002212' = 5.6
        '002220' = 6.5
        '002221' = 6.4
        '002222' = 5.5
        '010000' = 9.5
        '010001' = 9.4
        '010002' = 8.9
        '010010' = 9.4
        '010011' = 9.3
        '010012' = 8.4
        '010020' = 9.3
        '010021' = 9.2
        '010022' = 8.3
        '010100' = 9.1
        '010101' = 9.0
        '010102' = 8.5
        '010110' = 9.0
        '010111' = 8.9
        '010112' = 8.0
        '010120' = 8.9
        '010121' = 8.8
        '010122' = 7.9
        '010200' = 8.8
        '010201' = 8.7
        '010202' = 7.8
        '010210' = 8.7
        '010211' = 8.6
        '010212' = 7.7
        '010220' = 8.6
        '010221' = 8.5
        '010222' = 7.6
        '011000' = 8.2
        '011001' = 8.1
        '011002' = 7.2
        '011010' = 8.1
        '011011' = 8.0
        '011012' = 7.1
        '011020' = 8.0
        '011021' = 7.9
        '011022' = 7.0
        '011100' = 7.9
        '011101' = 7.8
        '011102' = 6.9
        '011110' = 7.8
        '011111' = 7.7
        '011112' = 6.8
        '011120' = 7.7
        '011121' = 7.6
        '011122' = 6.7
        '011200' = 7.6
        '011201' = 7.5
        '011202' = 6.6
        '011210' = 7.5
        '011211' = 7.4
        '011212' = 6.5
        '011220' = 7.4
        '011221' = 7.3
        '011222' = 6.4
        '012000' = 7.0
        '012001' = 6.9
        '012002' = 6.0
        '012010' = 6.9
        '012011' = 6.8
        '012012' = 5.9
        '012020' = 6.8
        '012021' = 6.7
        '012022' = 5.8
        '012100' = 6.7
        '012101' = 6.6
        '012102' = 5.7
        '012110' = 6.6
        '012111' = 6.5
        '012112' = 5.6
        '012120' = 6.5
        '012121' = 6.4
        '012122' = 5.5
        '012200' = 6.4
        '012201' = 6.3
        '012202' = 5.4
        '012210' = 6.3
        '012211' = 6.2
        '012212' = 5.3
        '012220' = 6.2
        '012221' = 6.1
        '012222' = 5.2
        '020000' = 9.1
        '020001' = 9.0
        '020002' = 8.5
        '020010' = 9.0
        '020011' = 8.9
        '020012' = 8.0
        '020020' = 8.9
        '020021' = 8.8
        '020022' = 7.9
        '020100' = 8.7
        '020101' = 8.6
        '020102' = 8.1
        '020110' = 8.6
        '020111' = 8.5
        '020112' = 7.6
        '020120' = 8.5
        '020121' = 8.4
        '020122' = 7.5
        '020200' = 8.4
        '020201' = 8.3
        '020202' = 7.4
        '020210' = 8.3
        '020211' = 8.2
        '020212' = 7.3
        '020220' = 8.2
        '020221' = 8.1
        '020222' = 7.2
        '021000' = 7.6
        '021001' = 7.5
        '021002' = 6.6
        '021010' = 7.5
        '021011' = 7.4
        '021012' = 6.5
        '021020' = 7.4
        '021021' = 7.3
        '021022' = 6.4
        '021100' = 7.3
        '021101' = 7.2
        '021102' = 6.3
        '021110' = 7.2
        '021111' = 7.1
        '021112' = 6.2
        '021120' = 7.1
        '021121' = 7.0
        '021122' = 6.1
        '021200' = 7.0
        '021201' = 6.9
        '021202' = 6.0
        '021210' = 6.9
        '021211' = 6.8
        '021212' = 5.9
        '021220' = 6.8
        '021221' = 6.7
        '021222' = 5.8
        '022000' = 6.4
        '022001' = 6.3
        '022002' = 5.4
        '022010' = 6.3
        '022011' = 6.2
        '022012' = 5.3
        '022020' = 6.2
        '022021' = 6.1
        '022022' = 5.2
        '022100' = 6.1
        '022101' = 6.0
        '022102' = 5.1
        '022110' = 6.0
        '022111' = 5.9
        '022112' = 5.0
        '022120' = 5.9
        '022121' = 5.8
        '022122' = 4.9
        '022200' = 5.8
        '022201' = 5.7
        '022202' = 4.8
        '022210' = 5.7
        '022211' = 5.6
        '022212' = 4.7
        '022220' = 5.6
        '022221' = 5.5
        '022222' = 4.6
        '100000' = 9.1
        '100001' = 9.0
        '100002' = 8.5
        '100010' = 9.0
        '100011' = 8.9
        '100012' = 8.0
        '100020' = 8.9
        '100021' = 8.8
        '100022' = 7.9
        '100100' = 8.7
        '100101' = 8.6
        '100102' = 8.1
        '100110' = 8.6
        '100111' = 8.5
        '100112' = 7.6
        '100120' = 8.5
        '100121' = 8.4
        '100122' = 7.5
        '100200' = 8.4
        '100201' = 8.3
        '100202' = 7.4
        '100210' = 8.3
        '100211' = 8.2
        '100212' = 7.3
        '100220' = 8.2
        '100221' = 8.1
        '100222' = 7.2
        '101000' = 7.6
        '101001' = 7.5
        '101002' = 6.6
        '101010' = 7.5
        '101011' = 7.4
        '101012' = 6.5
        '101020' = 7.4
        '101021' = 7.3
        '101022' = 6.4
        '101100' = 7.3
        '101101' = 7.2
        '101102' = 6.3
        '101110' = 7.2
        '101111' = 7.1
        '101112' = 6.2
        '101120' = 7.1
        '101121' = 7.0
        '101122' = 6.1
        '101200' = 7.0
        '101201' = 6.9
        '101202' = 6.0
        '101210' = 6.9
        '101211' = 6.8
        '101212' = 5.9
        '101220' = 6.8
        '101221' = 6.7
        '101222' = 5.8
        '102000' = 6.4
        '102001' = 6.3
        '102002' = 5.4
        '102010' = 6.3
        '102011' = 6.2
        '102012' = 5.3
        '102020' = 6.2
        '102021' = 6.1
        '102022' = 5.2
        '102100' = 6.1
        '102101' = 6.0
        '102102' = 5.1
        '102110' = 6.0
        '102111' = 5.9
        '102112' = 5.0
        '102120' = 5.9
        '102121' = 5.8
        '102122' = 4.9
        '102200' = 5.8
        '102201' = 5.7
        '102202' = 4.8
        '102210' = 5.7
        '102211' = 5.6
        '102212' = 4.7
        '102220' = 5.6
        '102221' = 5.5
        '102222' = 4.6
        '110000' = 8.7
        '110001' = 8.6
        '110002' = 8.1
        '110010' = 8.6
        '110011' = 8.5
        '110012' = 7.6
        '110020' = 8.5
        '110021' = 8.4
        '110022' = 7.5
        '110100' = 8.3
        '110101' = 8.2
        '110102' = 7.3
        '110110' = 8.2
        '110111' = 8.1
        '110112' = 7.2
        '110120' = 8.1
        '110121' = 8.0
        '110122' = 7.1
        '110200' = 8.0
        '110201' = 7.9
        '110202' = 7.0
        '110210' = 7.9
        '110211' = 7.8
        '110212' = 6.9
        '110220' = 7.8
        '110221' = 7.7
        '110222' = 6.8
        '111000' = 7.3
        '111001' = 7.2
        '111002' = 6.3
        '111010' = 7.2
        '111011' = 7.1
        '111012' = 6.2
        '111020' = 7.1
        '111021' = 7.0
        '111022' = 6.1
        '111100' = 7.0
        '111101' = 6.9
        '111102' = 6.0
        '111110' = 6.9
        '111111' = 6.8
        '111112' = 5.9
        '111120' = 6.8
        '111121' = 6.7
        '111122' = 5.8
        '111200' = 6.7
        '111201' = 6.6
        '111202' = 5.7
        '111210' = 6.6
        '111211' = 6.5
        '111212' = 5.6
        '111220' = 6.5
        '111221' = 6.4
        '111222' = 5.5
        '112000' = 6.1
        '112001' = 6.0
        '112002' = 5.1
        '112010' = 6.0
        '112011' = 5.9
        '112012' = 5.0
        '112020' = 5.9
        '112021' = 5.8
        '112022' = 4.9
        '112100' = 5.8
        '112101' = 5.7
        '112102' = 4.8
        '112110' = 5.7
        '112111' = 5.6
        '112112' = 4.7
        '112120' = 5.6
        '112121' = 5.5
        '112122' = 4.6
        '112200' = 5.5
        '112201' = 5.4
        '112202' = 4.5
        '112210' = 5.4
        '112211' = 5.3
        '112212' = 4.4
        '112220' = 5.3
        '112221' = 5.2
        '112222' = 4.3
        '120000' = 8.3
        '120001' = 8.2
        '120002' = 7.3
        '120010' = 8.2
        '120011' = 8.1
        '120012' = 7.2
        '120020' = 8.1
        '120021' = 8.0
        '120022' = 7.1
        '120100' = 7.9
        '120101' = 7.8
        '120102' = 6.9
        '120110' = 7.8
        '120111' = 7.7
        '120112' = 6.8
        '120120' = 7.7
        '120121' = 7.6
        '120122' = 6.7
        '120200' = 7.6
        '120201' = 7.5
        '120202' = 6.6
        '120210' = 7.5
        '120211' = 7.4
        '120212' = 6.5
        '120220' = 7.4
        '120221' = 7.3
        '120222' = 6.4
        '121000' = 7.0
        '121001' = 6.9
        '121002' = 6.0
        '121010' = 6.9
        '121011' = 6.8
        '121012' = 5.9
        '121020' = 6.8
        '121021' = 6.7
        '121022' = 5.8
        '121100' = 6.7
        '121101' = 6.6
        '121102' = 5.7
        '121110' = 6.6
        '121111' = 6.5
        '121112' = 5.6
        '121120' = 6.5
        '121121' = 6.4
        '121122' = 5.5
        '121200' = 6.4
        '121201' = 6.3
        '121202' = 5.4
        '121210' = 6.3
        '121211' = 6.2
        '121212' = 5.3
        '121220' = 6.2
        '121221' = 6.1
        '121222' = 5.2
        '122000' = 5.8
        '122001' = 5.7
        '122002' = 4.8
        '122010' = 5.7
        '122011' = 5.6
        '122012' = 4.7
        '122020' = 5.6
        '122021' = 5.5
        '122022' = 4.6
        '122100' = 5.5
        '122101' = 5.4
        '122102' = 4.5
        '122110' = 5.4
        '122111' = 5.3
        '122112' = 4.4
        '122120' = 5.3
        '122121' = 5.2
        '122122' = 4.3
        '122200' = 5.2
        '122201' = 5.1
        '122202' = 4.2
        '122210' = 5.1
        '122211' = 5.0
        '122212' = 4.1
        '122220' = 5.0
        '122221' = 4.9
        '122222' = 4.0
        '200000' = 8.8
        '200001' = 8.7
        '200002' = 7.8
        '200010' = 8.7
        '200011' = 8.6
        '200012' = 7.7
        '200020' = 8.6
        '200021' = 8.5
        '200022' = 7.6
        '200100' = 8.4
        '200101' = 8.3
        '200102' = 7.4
        '200110' = 8.3
        '200111' = 8.2
        '200112' = 7.3
        '200120' = 8.2
        '200121' = 8.1
        '200122' = 7.2
        '200200' = 8.1
        '200201' = 8.0
        '200202' = 7.1
        '200210' = 8.0
        '200211' = 7.9
        '200212' = 7.0
        '200220' = 7.9
        '200221' = 7.8
        '200222' = 6.9
        '201000' = 7.4
        '201001' = 7.3
        '201002' = 6.4
        '201010' = 7.3
        '201011' = 7.2
        '201012' = 6.3
        '201020' = 7.2
        '201021' = 7.1
        '201022' = 6.2
        '201100' = 7.1
        '201101' = 7.0
        '201102' = 6.1
        '201110' = 7.0
        '201111' = 6.9
        '201112' = 6.0
        '201120' = 6.9
        '201121' = 6.8
        '201122' = 5.9
        '201200' = 6.8
        '201201' = 6.7
        '201202' = 5.8
        '201210' = 6.7
        '201211' = 6.6
        '201212' = 5.7
        '201220' = 6.6
        '201221' = 6.5
        '201222' = 5.6
        '202000' = 6.2
        '202001' = 6.1
        '202002' = 5.2
        '202010' = 6.1
        '202011' = 6.0
        '202012' = 5.1
        '202020' = 6.0
        '202021' = 5.9
        '202022' = 5.0
        '202100' = 5.9
        '202101' = 5.8
        '202102' = 4.9
        '202110' = 5.8
        '202111' = 5.7
        '202112' = 4.8
        '202120' = 5.7
        '202121' = 5.6
        '202122' = 4.7
        '202200' = 5.6
        '202201' = 5.5
        '202202' = 4.6
        '202210' = 5.5
        '202211' = 5.4
        '202212' = 4.5
        '202220' = 5.4
        '202221' = 5.3
        '202222' = 4.4
        '210000' = 8.4
        '210001' = 8.3
        '210002' = 7.4
        '210010' = 8.3
        '210011' = 8.2
        '210012' = 7.3
        '210020' = 8.2
        '210021' = 8.1
        '210022' = 7.2
        '210100' = 8.0
        '210101' = 7.9
        '210102' = 7.0
        '210110' = 7.9
        '210111' = 7.8
        '210112' = 6.9
        '210120' = 7.8
        '210121' = 7.7
        '210122' = 6.8
        '210200' = 7.7
        '210201' = 7.6
        '210202' = 6.7
        '210210' = 7.6
        '210211' = 7.5
        '210212' = 6.6
        '210220' = 7.5
        '210221' = 7.4
        '210222' = 6.5
        '211000' = 7.0
        '211001' = 6.9
        '211002' = 6.0
        '211010' = 6.9
        '211011' = 6.8
        '211012' = 5.9
        '211020' = 6.8
        '211021' = 6.7
        '211022' = 5.8
        '211100' = 6.7
        '211101' = 6.6
        '211102' = 5.7
        '211110' = 6.6
        '211111' = 6.5
        '211112' = 5.6
        '211120' = 6.5
        '211121' = 6.4
        '211122' = 5.5
        '211200' = 6.4
        '211201' = 6.3
        '211202' = 5.4
        '211210' = 6.3
        '211211' = 6.2
        '211212' = 5.3
        '211220' = 6.2
        '211221' = 6.1
        '211222' = 5.2
        '212000' = 5.8
        '212001' = 5.7
        '212002' = 4.8
        '212010' = 5.7
        '212011' = 5.6
        '212012' = 4.7
        '212020' = 5.6
        '212021' = 5.5
        '212022' = 4.6
        '212100' = 5.5
        '212101' = 5.4
        '212102' = 4.5
        '212110' = 5.4
        '212111' = 5.3
        '212112' = 4.4
        '212120' = 5.3
        '212121' = 5.2
        '212122' = 4.3
        '212200' = 5.2
        '212201' = 5.1
        '212202' = 4.2
        '212210' = 5.1
        '212211' = 5.0
        '212212' = 4.1
        '212220' = 5.0
        '212221' = 4.9
        '212222' = 4.0
        '220000' = 8.0
        '220001' = 7.9
        '220002' = 7.0
        '220010' = 7.9
        '220011' = 7.8
        '220012' = 6.9
        '220020' = 7.8
        '220021' = 7.7
        '220022' = 6.8
        '220100' = 7.6
        '220101' = 7.5
        '220102' = 6.6
        '220110' = 7.5
        '220111' = 7.4
        '220112' = 6.5
        '220120' = 7.4
        '220121' = 7.3
        '220122' = 6.4
        '220200' = 7.3
        '220201' = 7.2
        '220202' = 6.3
        '220210' = 7.2
        '220211' = 7.1
        '220212' = 6.2
        '220220' = 7.1
        '220221' = 7.0
        '220222' = 6.1
        '221000' = 6.6
        '221001' = 6.5
        '221002' = 5.6
        '221010' = 6.5
        '221011' = 6.4
        '221012' = 5.5
        '221020' = 6.4
        '221021' = 6.3
        '221022' = 5.4
        '221100' = 6.3
        '221101' = 6.2
        '221102' = 5.3
        '221110' = 6.2
        '221111' = 6.1
        '221112' = 5.2
        '221120' = 6.1
        '221121' = 6.0
        '221122' = 5.1
        '221200' = 6.0
        '221201' = 5.9
        '221202' = 5.0
        '221210' = 5.9
        '221211' = 5.8
        '221212' = 4.9
        '221220' = 5.8
        '221221' = 5.7
        '221222' = 4.8
        '222000' = 5.4
        '222001' = 5.3
        '222002' = 4.4
        '222010' = 5.3
        '222011' = 5.2
        '222012' = 4.3
        '222020' = 5.2
        '222021' = 5.1
        '222022' = 4.2
        '222100' = 5.1
        '222101' = 5.0
        '222102' = 4.1
        '222110' = 5.0
        '222111' = 4.9
        '222112' = 4.0
        '222120' = 4.9
        '222121' = 4.8
        '222122' = 3.9
        '222200' = 4.8
        '222201' = 4.7
        '222202' = 3.8
        '222210' = 4.7
        '222211' = 4.6
        '222212' = 3.7
        '222220' = 4.6
        '222221' = 4.5
        '222222' = 3.6
    }

    # Validate vector format
    if ($CVSSVector -notmatch '^CVSS:4\.0/AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NAP]/VC:[NLH]/VI:[NLH]/VA:[NLH]/SC:[NLH]/SI:[NLH]/SA:[NLH](/(CR|IR|AR|MAV|MAC|MAT|MPR|MUI|MVC|MVI|MVA|MSC|MSI|MSA|R|V|RE|U):[A-Z])?$') {
        throw "Invalid CVSS v4.0 string format"
    }

    $vector = $CVSSVector -replace '^CVSS:4\.0/', ''
    $parts = @{}
    foreach ($part in $vector.Split('/')) {
        if ($part -match '^([A-Z]{1,3}):([A-Z]{1,2})$') {
            $parts[$Matches[1]] = $Matches[2]
        }
    }

    # Apply defaults for environmental/supplemental metrics
    $defaultMetrics = @{
        CR = 'M'; IR = 'M'; AR = 'M';
        MAV = 'X'; MAC = 'X'; MAT = 'X'; MPR = 'X'; MUI = 'X'; MVC = 'X'; MVI = 'X'; MVA = 'X'; MSC = 'X'; MSI = 'X'; MSA = 'X';
        R = 'X'; V = 'X'; RE = 'X'; U = 'X'
    }
    foreach ($metric in $defaultMetrics.Keys) {
        if (-not $parts.ContainsKey($metric)) {
            $parts[$metric] = $defaultMetrics[$metric]
        }
    }

    # Validate required metrics
    $required = @('AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA')
    foreach ($r in $required) {
        if (-not $parts.ContainsKey($r)) {
            throw "Required metric '$r' missing in vector."
        }
    }

    # Determine Scope for PR calculation
    $scopeChanged = ($parts['SC'] -eq 'H' -or $parts['SI'] -eq 'H' -or $parts['SA'] -eq 'H') ? 'C' : 'U'

    # Calculate Equivalence Classes (EQ1–EQ6)
    # EQ1: Exploitability (AV, PR, UI)
    $EQ1 = if ($parts['AV'] -in @('N', 'A', 'L') -and $parts['PR'] -in @('N', 'L') -and $parts['UI'] -in @('N', 'A')) { 0 }
           elseif ($parts['AV'] -eq 'P' -or $parts['PR'] -eq 'H' -or $parts['UI'] -eq 'P') { 1 }
           else { 2 }

    # EQ2: Complexity (AC, AT)
    $EQ2 = if ($parts['AC'] -eq 'L' -and $parts['AT'] -eq 'N') { 0 } else { 1 }

    # EQ3: Vulnerable System Impact (VC, VI, VA)
    $EQ3 = if ($parts['VC'] -eq 'H' -or $parts['VI'] -eq 'H' -or $parts['VA'] -eq 'H') { 0 }
           elseif ($parts['VC'] -eq 'L' -or $parts['VI'] -eq 'L' -or $parts['VA'] -eq 'L') { 1 }
           else { 2 }

    # EQ4: Automatable (AV)
    $EQ4 = if ($parts['AV'] -in @('N', 'A', 'L')) { 0 } else { 1 }

    # EQ5: Safety Impact (MSI, MSA) - defaults to 0 if not specified
    $EQ5 = 0  # Assume no safety impact unless specified

    # EQ6: Subsequent System Impact (SC, SI, SA)
    $EQ6 = if ($parts['SC'] -eq 'H' -or $parts['SI'] -eq 'H' -or $parts['SA'] -eq 'H') { 0 }
           elseif ($parts['SC'] -eq 'L' -or $parts['SI'] -eq 'L' -or $parts['SA'] -eq 'L') { 1 }
           else { 2 }

    # Form macro vector key
    $macroKey = "$EQ1$EQ2$EQ3$EQ4$EQ5$EQ6"

    # Lookup base score
    $BaseScore = if ($macroLookup.ContainsKey($macroKey)) { $macroLookup[$macroKey] } else { 0.0 }

    return $BaseScore
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

    $purlRegex = '^pkg:[a-z0-9.+-]+/[a-zA-Z0-9._\-]+(/[a-zA-Z0-9._\-]+)*(@[^?\s]+)?(\?[^\s#]*)?(#[^\s]*)?$'

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
        $body = @{
            "package" = @{
                "purl" = $purl.purl
            }
        } | ConvertTo-Json

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

                    if ($vulnerability.severity.score.contains("3.0")) {
                        #CVSS 3.0
                        $scoreuri = "https://www.first.org/cvss/calculator/3-0#"
                        $vuln.ScoreURI = $scoreuri + $vulnerability.severity.score
                        try {
                            $vuln.Score = Convert-CVSS3StringToBaseScore $vulnerability.severity.score
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
                    } elseif ($vulnerability.severity.score.contains("3.1")) {
                        #CVSS 3.1
                        $scoreuri = "https://www.first.org/cvss/calculator/3-1#"
                        $vuln.ScoreURI = $scoreuri + $vulnerability.severity.score
                        try {
                            $vuln.Score = Convert-CVSS3StringToBaseScore $vulnerability.severity.score
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
                    } elseif ($vulnerability.severity.score.contains("4.0")) {
                        #CVSS 4.0
                        $scoreuri = "https://www.first.org/cvss/calculator/4-0#"
                        $vuln.ScoreURI = $scoreuri + $vulnerability.severity.score
                        try {
                            $vuln.Score = Convert-CVSS4StringToBaseScore $vulnerability.severity.score
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
                Write-Output "OSV found no vulnerabilities for $(purl.purl)" | Out-File -FilePath $outfile -Append
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
    [OutputType([System.Collections.Generic.List[PSObject]])]
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
    [OutputType([System.Collections.Generic.List[PSObject]])]
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

                #if ($components.count -lt 3) {
                while ($components.count -lt 3) {
                    $testversion += ".0"
                    $components = $testVersion.Split('.')
                }
            }

            $testName = Get-NameFromPurl -purl $package.externalRefs.referenceLocator
            if ($testName -eq "") {
                $testName = ($package.name).Replace(':','/')
                $purlString = "pkg:" + $testName + "@" + $testVersion
                $parts = $testname.split('/')
                if ($parts.count -gt 1) {
                    $testName = $parts[1]
        } else {
                    $testName = $parts[0]
                }
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

#SBOMResearcher -SBOMPath "C:\Temp\SBOMResearcher\smalltest" -wrkDir "C:\Temp\SBOMResearcher\reports" -PrintLicenseInfo $true -minScore 7.0
