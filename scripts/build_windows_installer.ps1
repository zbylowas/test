param(
    [Parameter(Mandatory)][string]$WixDirectory,
    [Parameter(Mandatory)][string]$Executable,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [Parameter(Mandatory)][string]$SignTool
)
$ErrorActionPreference='Stop'
$exe=(Get-Item -LiteralPath $Executable).FullName
$version=(Get-Item -LiteralPath $exe).VersionInfo.ProductVersion
if ($version -notmatch '^\d+\.\d+\.\d+$') {throw 'Missing EXE product version'}
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$wix=(Resolve-Path -LiteralPath $WixDirectory).Path
$build=New-Item -ItemType Directory -Path $OutputDirectory
$wxs=Join-Path $root 'deploy/windows-installer.wxs'
$rtf=Join-Path $build.FullName 'LICENSE.rtf'
$license=[IO.File]::ReadAllText((Join-Path $root 'LICENSE')).Replace('\','\\').Replace('{','\{').Replace('}','\}')
[IO.File]::WriteAllText($rtf,'{\rtf1\ansi '+($license -replace '\r?\n','\par ')+ '}')
$obj=Join-Path $build.FullName 'installer.wixobj'
& (Join-Path $wix 'candle.exe') -nologo -arch x64 "-dVersion=$version" "-dExe=$exe" "-dLicenseRtf=$rtf" -out $obj $wxs
if ($LASTEXITCODE -ne 0) {throw 'WiX failed to compile installer'}
$msi=Join-Path $build.FullName 'VIP-NET-Diagnostyka-Setup.msi'
& (Join-Path $wix 'light.exe') -nologo -cultures:pl-pl -ext (Join-Path $wix 'WixUIExtension.dll') -out $msi $obj
if ($LASTEXITCODE -ne 0) {throw 'WiX failed to link installer'}
$cert=[System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
    [Convert]::FromBase64String([IO.File]::ReadAllText((Join-Path $root 'client/windows/project-signer.b64'))))
& $SignTool sign /fd SHA256 /sha1 $cert.Thumbprint /tr 'http://timestamp.digicert.com' /td SHA256 $msi
if ($LASTEXITCODE -ne 0) {throw 'Installer signing failed'}
$signature=Get-AuthenticodeSignature -LiteralPath $msi
if ($signature.SignerCertificate.Thumbprint -ne $cert.Thumbprint -or -not $signature.TimeStamperCertificate -or
    $signature.Status -notin @('Valid','UnknownError','NotTrusted')) {
    throw 'Unexpected installer signature'
}
Write-Output $msi
