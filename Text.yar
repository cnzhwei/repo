rule Trojan_VBS_Agent_mppreference_Dev
{
        
        meta:
               
                author = "tangxi"
                check = "2021/10/11 tangxi"
                hash = "6b5cf02e78047304342329ad6834eb2e63285e2d313048760c4e8ddd83d43056"
                //$s1= CreateObject("WScript.Shell").Run 
                //#s0 = "powershell Add-MpPreference -ExclusionPath [10-200].exe'", 0, False
                
        strings:
                $s0 = {22 70 6F 77 65 72 73 68 65 6C 6C 20 41 64 64 2D 4D 70 50 72 65 66 65 72 65 6E 63 65 20 2D 45 78 63 6C 75 73 69 6F 6E 50 61 74 68 20 [10-200] 2E 65 78 65 27 22 2C 20 30 2C 20 46 61 6C 73 65}
                $s1 = "CreateObject(\"WScript.Shell\").Run "
        condition:
                 all of ($s*)
                
}

rule Sus_Trojan_VBS_Agent_reg_Dev
{
        
        meta:
               
                author = "tangxi"
                check = "2021/10/11 tangxi"
                updata = "2022/4/26 tangxi"
                hash = "b74361c6595f1fc68a8318b19d84bedbaf09e65ac48af025f7c24d9ba4fa590c"
                
                
        strings:
        		//$s0 = WshShell.RegWrite myKey,[3-200].vbs","REG_SZ"
                //$s1 = WshShell.RegWrite myKey,Vbs,"REG_SZ" nocase
                //$m0 = WshShell.Run [3-200].exe
                $s0 = {57 73 68 53 68 65 6C 6C 2E 52 65 67 57 72 69 74 65 20 6D 79 4B 65 79 2C [3-200] 2E 76 62 73 22 2C 22 52 45 47 5F 53 5A 22}
                $s1 = "WshShell.RegWrite myKey,Vbs,\"REG_SZ\"" nocase
                $m0 = {57 73 68 53 68 65 6C 6C 2E 52 75 6E 20 [3-200] 2E 65 78 65}
        condition:
                 1 of ($s*) and all of ($m*)
                
}
