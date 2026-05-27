rule eicar_test_string
{
    meta:
        description = "Detect the EICAR test file string"
        severity = "critical"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule suspicious_script_download
{
    meta:
        description = "Detect suspicious script downloader patterns"
        severity = "high"
    strings:
        $ps1 = /powershell(\.exe)?\s+-e(ncodedcommand)?/ nocase
        $wscript = "WScript.Shell" nocase
        $bitsadmin = "bitsadmin" nocase
        $certutil = "certutil -urlcache" nocase
    condition:
        2 of them
}

