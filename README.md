# IdentityServer-Certs---Powershell

# Only works on Win10/Server 2016

Auth X509 Cert
```
[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)][string]$password = "YOUR_PASSWORD",
    [Parameter(Mandatory=$false)][string]$rootDomain = "YOUR_DOMAIN"
)

$cwd = "C:\certificates"
$sCerFile = "$cwd\cer\token_signing.cer"
$sPfxFile = "$cwd\pfx\token_signing.pfx"
$vCerFile = "$cwd\cer\token_validation.cer"
$vPfxFile = "$cwd\pfx\token_validation.pfx"

# abort if files exist
if((Test-Path($sPfxFile)) -or (Test-Path($sCerFile)) -or (Test-Path($vPfxFile)) -or (Test-Path($vCerFile)))
{
    Write-Warning "Failed, token_signing or token_validation files already exist in current directory."
    Exit
}

function Get-NewCert ([string]$name)
{
    New-SelfSignedCertificate `
        -Subject $rootDomain `
        -DnsName $rootDomain `
        -FriendlyName $name `
        -NotBefore (Get-Date) `
        -NotAfter (Get-Date).AddYears(10) `
        -CertStoreLocation "cert:LocalMachine\My" `
        -KeyAlgorithm RSA `
        -KeyLength 4096 `
        -HashAlgorithm SHA256 `
        -KeyUsage DigitalSignature, KeyEncipherment, DataEncipherment `
        -Type Custom,DocumentEncryptionCert `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1")
}

$securePass = ConvertTo-SecureString -String $password -Force -AsPlainText

# token signing certificate
$cert = Get-NewCert("IDS Token Signing Credentials")
$store = 'Cert:\LocalMachine\My\' + ($cert.ThumbPrint)  
Export-PfxCertificate -Cert $store -FilePath $sPfxFile -Password $securePass
Export-Certificate -Cert $store -FilePath $sCerFile
Write-Host "Token-signing thumbprint: " $cert.Thumbprint

# token validation certificate
$cert =  Get-NewCert("IDS Token Validation Credentials")
$store = 'Cert:\LocalMachine\My\' + ($cert.ThumbPrint)  
Export-PfxCertificate -Cert $store -FilePath $vPfxFile -Password $securePass
Export-Certificate -Cert $store -FilePath $vCerFile
Write-Host "Token-validation thumbprint: " $cert.Thumbprint
```

SSL Cert
```
[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$password = "YOUR_PASSWORD"
)

$cwd = "C:\certificates"
$cerFile = "$cwd\cer\localhost.cer"
$pfxFile = "$cwd\pfx\localhost.pfx"

# abort if files exist
if((Test-Path($pfxFile)) -or (Test-Path($cerFile)))
{
    Write-Warning "Failed, localhost files already exist in current directory."
    Exit
}

# include DnsName property for modern browsers
# https://groups.google.com/a/chromium.org/forum/#!topic/security-dev/IGT2fLJrAeo
$cert = New-SelfSignedCertificate `
    -Subject localhost `
    -DnsName localhost `
    -FriendlyName "Localhost Dev Certificate" `
    -NotBefore (Get-Date) `
    -NotAfter (Get-Date).AddYears(10) `
    -CertStoreLocation "cert:LocalMachine\My" `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -HashAlgorithm SHA256 `
    -KeyUsage DigitalSignature, KeyEncipherment, DataEncipherment `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1") 

$certStore = 'Cert:\LocalMachine\My\' + ($cert.ThumbPrint)  
$securePass = ConvertTo-SecureString -String $password -Force -AsPlainText

Export-PfxCertificate -Cert $certStore -FilePath $pfxFile -Password $securePass
Export-Certificate -Cert $certStore -FilePath $cerFile
```

```
X509Certificate2 signingCert    = X509.LocalMachine.My.Thumbprint.Find("THUMBPRINT 1", false).First();
X509Certificate2 validationCert = X509.LocalMachine.My.Thumbprint.Find("THUMBPRINT 2", false).First();
```

```
services.AddIdentityServer()
                    .AddSigningCredential(signingCert)
                    .AddValidationKey(validationCert)
```
