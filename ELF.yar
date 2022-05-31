rule Sus_Trojan_VBS_Agent_debug_Dev
{
        
        meta:
               
                author = "tangxi"
                check = "2021/10/11 tangxi"
                updata = "2022/4/25 tangxi"
                hash = "009d2c2eb56d7b91d8409df2dd449fedffdde6131f566b32c2c5a09b127ec6fa"
                // $s0 = Sub [0-50]Debug.Print "pox" + x + "iii"[0-10]End Sub
                
        strings:
                $s0 = {53 75 62 20 [0-50] 44 65 62 75 67 2E 50 72 69 6E 74 20 22 70 6F 78 22 20 2B 20 78 20 2B 20 22 69 69 69 22 [0-10] 45 6E 64 20 53 75 62}
        condition:
                filesize<1KB and 1 of ($s*) 
                
}

rule Trojan_VBS_Agent_sleep_Dev 
{
        
        meta:
               
                author = "tangxi"
                check = "2021/10/11 tangxi"
                hash = "14b7f12e24986485a70b8606d1eb976491f1756ca38a2f673977df3dfabf6ad8"
                /*
				objFSO = CreateObject("Scripting.FileSystemObject")
				wscript.sleep 1000
				objFSO.DeleteFile("[10-200].exe"), True  
				6F 62 6A 46 53 4F 2E 44 65 6C 65 74 65 46 69 6C 65 28 22 [10-200] 2E 65 78 65 22 29 2C 20 54 72 75 65
				createobject("scripting.filesystemobject").deletefile wscript.scriptfullname
				*/
 
       strings:
                $s0  = "objFSO = CreateObject(\"Scripting.FileSystemObject\")"
                $s1 = "wscript.sleep 1000"
                $s2 = {6F 62 6A 46 53 4F 2E 44 65 6C 65 74 65 46 69 6C 65 28 22 [10-200] 2E 65 78 65 22 29 2C 20 54 72 75 65}
                $s3 = "createobject(\"scripting.filesystemobject\").deletefile wscript.scriptfullname"
        
        condition:
                all of ($s*)
}
