[CmdletBinding(DefaultParameterSetName='Binaries')]
param(
    [Parameter(Mandatory,ParameterSetName='Binaries')][string]$BuildDirectory,
    [Parameter(Mandatory,ParameterSetName='Binaries')][string]$OutputDirectory,
    [Parameter(Mandatory,ParameterSetName='Binaries')][string]$SignTool,
    [Parameter(Mandatory,ParameterSetName='Manifest')][string]$Manifest
)
$ErrorActionPreference='Stop'
$public=[System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
    [Convert]::FromBase64String([IO.File]::ReadAllText((Join-Path $PSScriptRoot '../client/windows/project-signer.b64'))))
$cert=Get-Item -LiteralPath ('Cert:\CurrentUser\My\'+$public.Thumbprint)
if (-not $cert.HasPrivateKey) { throw 'The release key is unavailable.' }
if ($PSCmdlet.ParameterSetName -eq 'Manifest') {
    $m=Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json
    $message="VIP-NET Windows x64"+[char]10+$m.version+[char]10+$m.size+[char]10+$m.sha256+[char]10
    $rsa=[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    try {
        $proof=$rsa.SignData([Text.Encoding]::ASCII.GetBytes($message),
            [Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
        [Convert]::ToBase64String($proof)
    } finally { $rsa.Dispose() }
    return
}
if(Test-Path -LiteralPath $OutputDirectory){throw 'Choose a new output directory.'}
$folder=New-Item -ItemType Directory -Path $OutputDirectory
foreach($name in 'VIP-NET-Diagnostyka.exe','vipnet-mtr.exe'){
    $dest=Join-Path $folder.FullName $name
    Copy-Item -LiteralPath (Join-Path $BuildDirectory $name) -Destination $dest
    & $SignTool sign /fd SHA256 /sha1 $cert.Thumbprint /tr 'http://timestamp.digicert.com' /td SHA256 $dest
    if($LASTEXITCODE -ne 0){throw "Signing failed for $name"}
}
