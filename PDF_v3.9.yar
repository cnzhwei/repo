import "pe"

//AIS Test Rules

rule ABC_common_ddt
{
    meta:
        info = "test rule"
    strings:
        $s = "5725-4a23-a300"
    condition:
        $s
}

rule Yes_or_No
{
    meta:
        info = "test rule"
    strings:
        $s = "4b33-9153-1f96456c8dea"
    condition:
        $s
}

