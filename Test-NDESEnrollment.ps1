Function Test-NDESEnrollment {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True)]
        [String]
        $ComputerName,

        [Parameter(Mandatory=$True)]
        [String]
        $CommonName = "TestNDESCert",

        [Parameter(Mandatory=$False)]
        [String]
        $ChallengePassword,

        [Parameter(Mandatory=$False)]
        [Switch]
        $UseSSL = $False,

        [Parameter(Mandatory=$False)]
        [ValidateSet(1024,2048,3072,4096)]
        [Int]
        $KeyLength = 2048,

        [Parameter(Mandatory=$False)]
        [Switch]
        $MachineContext = $False
    )

    begin {
        $SCEPProcessDefault = 0x0
        #$SCEPProcessSkipCertInstall = 0x1
    
        $XCN_CRYPT_STRING_BASE64HEADER = 0x0

        $SCEPDispositionSuccess = 0
        $SCEPDispositionFailure = 2
    }

    process {

        If ($UseSSL) 
            { $Protocol = "https" }
        Else 
            { $Protocol = "http" }

        $ConfigString = "$($Protocol)://$($ComputerName)/certsrv/mscep/mscep.dll/pkiclient.exe"
    
        $Pkcs10 = New-Object -ComObject "X509Enrollment.CX509CertificateRequestPkcs10"
        $Pkcs10.Initialize([Int]($MachineContext -eq $True))

        $Subject = New-Object -ComObject "X509Enrollment.CX500DistinguishedName"
        $Subject.Encode("CN=$CommonName")
    
        $Pkcs10.Subject = $Subject
        $Pkcs10.KeyContainerNamePrefix = "NDESTest"

        If ($ChallengePassword) {
            $Pkcs10.ChallengePassword = $ChallengePassword
        }
    
        $Pkcs10.PrivateKey.Length = $KeyLength

        $Helper = New-Object -ComObject "X509Enrollment.CX509SCEPEnrollmentHelper"

        $Helper.Initialize(
            $ConfigString,
            [String]::Empty,
            $Pkcs10,
            [String]::Empty
            )

        $Disposition = $Helper.Enroll($SCEPProcessDefault)

        switch ($Disposition) {
            $SCEPDispositionFailure {
                Write-Error $Helper.ResultMessageText
            }
            $SCEPDispositionSuccess {
                $Helper.X509SCEPEnrollment.Certificate($XCN_CRYPT_STRING_BASE64HEADER)
            }
            default {
                Write-Host "X509SCEPDisposition: $Disposition"
            }
        }
    }

}