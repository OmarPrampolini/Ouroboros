$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

param(
    [string]$Tag = $(if ($env:OUROBOROS_VERSION) { $env:OUROBOROS_VERSION } else { "latest" }),
    [string]$InstallDir = $(if ($env:OUROBOROS_INSTALL_DIR) { $env:OUROBOROS_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "Programs\Ouroboros\bin" }),
    [string]$Repo = $(if ($env:OUROBOROS_REPO) { $env:OUROBOROS_REPO } else { "OmarPrampolini/Ouroboros" }),
    [switch]$NoPathUpdate
)

function Resolve-ReleaseTag {
    param([string]$RequestedTag, [string]$Repository)

    if ($RequestedTag -ne "latest") {
        return $RequestedTag
    }

    $apiUrl = "https://api.github.com/repos/$Repository/releases/latest"
    $release = Invoke-RestMethod -Method Get -Uri $apiUrl
    if (-not $release.tag_name) {
        throw "Failed to resolve latest release tag from $apiUrl"
    }
    return [string]$release.tag_name
}

function Resolve-Target {
    $arch = $env:PROCESSOR_ARCHITECTURE
    switch ($arch.ToUpperInvariant()) {
        "AMD64" { return "x86_64-pc-windows-msvc" }
        default { throw "Unsupported Windows architecture: $arch" }
    }
}

function Get-ExpectedChecksum {
    param(
        [string]$ChecksumsPath,
        [string]$AssetName
    )

    foreach ($line in Get-Content $ChecksumsPath) {
        if ($line -match "^(?<hash>[a-fA-F0-9]{64})\s\s(?<name>.+)$" -and $Matches.name -eq $AssetName) {
            return $Matches.hash.ToLowerInvariant()
        }
    }

    throw "Checksum entry missing for $AssetName"
}

function Ensure-PathContains {
    param([string]$Directory)

    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $parts = @()
    if ($currentPath) {
        $parts = $currentPath.Split(';', [System.StringSplitOptions]::RemoveEmptyEntries)
    }

    if ($parts -contains $Directory) {
        return
    }

    $newPath = if ([string]::IsNullOrWhiteSpace($currentPath)) {
        $Directory
    } else {
        "$currentPath;$Directory"
    }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
}

$resolvedTag = Resolve-ReleaseTag -RequestedTag $Tag -Repository $Repo
$target = Resolve-Target
$asset = "handshacke-$resolvedTag-$target.zip"
$baseUrl = "https://github.com/$Repo/releases/download/$resolvedTag"

$tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ouroboros-install-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null

try {
    $archivePath = Join-Path $tmpDir $asset
    $checksumsPath = Join-Path $tmpDir "SHA256SUMS"
    $extractDir = Join-Path $tmpDir "extract"

    Write-Host "Downloading $asset"
    Invoke-WebRequest -Uri "$baseUrl/$asset" -OutFile $archivePath
    Invoke-WebRequest -Uri "$baseUrl/SHA256SUMS" -OutFile $checksumsPath

    $expected = Get-ExpectedChecksum -ChecksumsPath $checksumsPath -AssetName $asset
    $actual = (Get-FileHash -Algorithm SHA256 -Path $archivePath).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
        throw "Checksum mismatch for $asset"
    }

    New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
    Expand-Archive -Path $archivePath -DestinationPath $extractDir -Force

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item (Join-Path $extractDir "handshacke.exe") (Join-Path $InstallDir "handshacke.exe") -Force
    Copy-Item (Join-Path $extractDir "hs-cli.exe") (Join-Path $InstallDir "hs-cli.exe") -Force

    if (-not $NoPathUpdate) {
        Ensure-PathContains -Directory $InstallDir
    }

    Write-Host ""
    Write-Host "Installed handshacke.exe and hs-cli.exe to $InstallDir"
    if ($NoPathUpdate) {
        Write-Host "Add this directory to PATH if needed:"
        Write-Host "  $InstallDir"
    } else {
        Write-Host "User PATH updated if needed. Open a new shell to pick it up."
    }
    Write-Host ""
    Write-Host "Suggested next steps:"
    Write-Host "  handshacke"
    Write-Host "  hs-cli doctor"
}
finally {
    if (Test-Path $tmpDir) {
        Remove-Item -Recurse -Force $tmpDir
    }
}
