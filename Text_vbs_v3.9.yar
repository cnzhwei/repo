import "pe"

//AIS Test Rules

rule APT_common_hdd_123
{
    meta:
        info = "AIS"
    strings:
        $s = "68353c65"
    condition:
        $s
}

rule Backdoor_common_y3o_test
{
    meta:
        info = "AIS"
    strings:
        $s = "ec2e-4b33-9153"
    condition:
        $s
}

