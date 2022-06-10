import "pe"

//AIS Test Rules

rule PE_co13mmon_123_tp
{
    meta:
        info = "rule"
    strings:
        $s = "c3f2ca6b3652"
    condition:
        $s
}

rule Front_common_as_test
{
    meta:
        info = "ru2le"
    strings:
        $s = "456c8dea"
    condition:
        $s
}

