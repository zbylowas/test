param(
    [Parameter(Mandatory)][string]$Directory,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$PublisherSha256,
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version
)

$ErrorActionPreference = 'Stop'
$checksums = foreach ($name in 'VIP-NET-Diagnostyka.exe', 'vipnet-mtr.exe') {
    $file = Get-Item -LiteralPath (Join-Path $Directory $name)
    if ($file.VersionInfo.CompanyName -cne 'vip-net.pl' -or
        $file.VersionInfo.ProductName -cne 'VIP-NET Internet Diagnostics' -or
        $file.VersionInfo.ProductVersion -cne $Version) {
        throw "Unexpected Windows product metadata in $name"
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or -not $signature.TimeStamperCertificate) {
        throw "Missing trusted timestamped Authenticode signature in $name"
    }
    $publisherHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($signature.SignerCertificate.RawData))
    if ($publisherHash -ne $PublisherSha256) {
        throw "Unexpected publisher certificate for $name"
    }

    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $name"
}
$checksums | Set-Content -LiteralPath (Join-Path $Directory 'SHA256SUMS.txt') -Encoding ascii
