import "pe"

//AIS Test Rules

rule APT_common_AISTest
{
    meta:
        info = "AIS test rule"
    strings:
        $s = "68353c65-5725-4a23-a300-c3f2ca6b3652"
    condition:
        $s
}

rule Backdoor_common_AISTest
{
    meta:
        info = "AIS test rule"
    strings:
        $s = "82cc2dd6-ec2e-4b33-9153-1f96456c8dea"
    condition:
        $s
}

