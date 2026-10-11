#Requires -Version 7.0
<#
  Shared payload staging for every Windows package format.

  Why shared: the portable zip, the MSI and the winget package must all contain the same
  tree. Three copies of the launcher templates would drift, and the drift would only show up
  after a release.

  The staged tree is:
    <root>/bin/*.cmd      launchers, generated here (a source checkout points at cli/ and
                          mcp/ while a package points at dist/, so they cannot be copied)
    <root>/dist/*.cjs     the bundled payload
    <root>/README.md
    <root>/LICENSE

  AIKAWAMEI_TARGET in a launcher only sets a default; an explicit --target always wins.
#>

function Get-AikawaMeiVersion {
  param([Parameter(Mandatory)][string]$Repo)
  (Get-Content (Join-Path $Repo 'package.json') -Raw | ConvertFrom-Json).version
}

function Invoke-AikawaMeiBundle {
  param([Parameter(Mandatory)][string]$Repo, [string]$OutDir = 'dist')
  # Route the bundler's log through the host rather than the pipeline: a function's pipeline
  # output is its return value, and letting these lines through turned the path this function
  # returns into an array (observed as "cannot convert argument Root").
  & node (Join-Path $Repo 'packaging\bundle.mjs') --format cjs --outdir $OutDir |
    ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
  if ($LASTEXITCODE -ne 0) { throw "bundling failed" }
  foreach ($f in @("$OutDir\cli.cjs", "$OutDir\mcp.cjs")) {
    if (-not (Test-Path (Join-Path $Repo $f))) { throw "bundle missing: $f" }
  }
}

function New-AikawaMeiLauncher {
  param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$File,
    [ValidateSet('cli', 'mcp')][string]$Mode = 'cli',
    [string]$Pinned
  )
  $pin = if ($Pinned) { "set `"AIKAWAMEI_TARGET=$Pinned`"" } else { 'rem no pinned target: auto-detect' }
  $entry = if ($Mode -eq 'mcp') { 'mcp.cjs' } else { 'cli.cjs' }
  $note = if ($Mode -eq 'mcp') {
    'MCP stdio server. stdout carries the protocol, so nothing is echoed here.'
  } else {
    'Command-line interface.'
  }
  $text = @"
@echo off
rem AikawaMei - $note
rem AIKAWAMEI_TARGET only sets a default; an explicit --target still wins.
setlocal
$pin
node "%~dp0..\dist\$entry" %*
exit /b %ERRORLEVEL%
"@
  $binDir = Join-Path $Root 'bin'
  New-Item -ItemType Directory -Force -Path $binDir | Out-Null
  # CRLF: these are Windows batch files regardless of what platform builds them.
  Set-Content -LiteralPath (Join-Path $binDir $File) -Value ($text -replace "`r?`n", "`r`n") -Encoding ASCII -NoNewline
}

<#
  Stage the full payload. Returns the staged root path.
#>
function Stage-AikawaMeiPayload {
  param(
    [Parameter(Mandatory)][string]$Repo,
    [Parameter(Mandatory)][string]$Root,
    [ValidateSet('all', 'tor', 'firefox')][string]$Target = 'all',
    [switch]$SkipBundle
  )

  if (-not $SkipBundle) { Invoke-AikawaMeiBundle -Repo $Repo }

  if (Test-Path $Root) { Remove-Item $Root -Recurse -Force }
  New-Item -ItemType Directory -Force -Path (Join-Path $Root 'dist'), (Join-Path $Root 'bin') | Out-Null

  Copy-Item (Join-Path $Repo 'dist\cli.cjs') (Join-Path $Root 'dist\cli.cjs') -Force
  Copy-Item (Join-Path $Repo 'dist\mcp.cjs') (Join-Path $Root 'dist\mcp.cjs') -Force
  Copy-Item (Join-Path $Repo 'README.md') (Join-Path $Root 'README.md') -Force
  Copy-Item (Join-Path $Repo 'LICENSE') (Join-Path $Root 'LICENSE') -Force

  # The emblem travels beside the code it belongs to. It is copied when present rather than
  # required, so a checkout that has not sealed one still packages; the tool reports it as
  # absent in that case, which is a fact rather than a failure. The MSI harvests this
  # directory with a wildcard, so it picks the file up without a further change.
  # The name is READ OUT of lib/emblem.mjs rather than repeated here. It was repeated here, and when
  # the emblem file was renamed this line went on copying a name that no longer existed -- silently,
  # because the copy is conditional. One source of truth for a name is the whole of the fix.
  $emblemName = (Select-String -Path (Join-Path $Repo 'lib\emblem.mjs') `
      -Pattern 'EMBLEM_FILE\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
  $emblem = Join-Path $Repo $emblemName
  if (Test-Path $emblem) { Copy-Item $emblem (Join-Path $Root $emblemName) -Force }

  $targets = if ($Target -eq 'all') { @($null, 'tor', 'firefox') } else { @($Target) }
  foreach ($t in $targets) {
    if ($t) {
      New-AikawaMeiLauncher -Root $Root -File "aikawamei-$t.cmd" -Mode cli -Pinned $t
      New-AikawaMeiLauncher -Root $Root -File "aikawamei-$t-mcp.cmd" -Mode mcp -Pinned $t
    } else {
      New-AikawaMeiLauncher -Root $Root -File 'aikawamei.cmd' -Mode cli
      New-AikawaMeiLauncher -Root $Root -File 'aikawamei-mcp.cmd' -Mode mcp
    }
  }

  return $Root
}

function New-AikawaMeiPortableNote {
  param([Parameter(Mandatory)][string]$Root, [string]$Target = 'all', [string]$Version)
  $launchers = (Get-ChildItem (Join-Path $Root 'bin') -Filter *.cmd | Select-Object -ExpandProperty Name) -join "`r`n  "
  $note = @"
AikawaMei $Version - portable distribution ($Target)

Requires Node.js >= 18 on PATH. Nothing is installed; run the launchers from anywhere.

  $launchers

CLI usage:
  bin\aikawamei.cmd --help
  bin\aikawamei-tor.cmd aikawamei_audit --human
  bin\aikawamei-firefox.cmd aikawamei_audit --human

MCP stdio server: point a client at a -mcp launcher, for example
  bin\aikawamei-firefox-mcp.cmd

A launcher only sets a default target (AIKAWAMEI_TARGET). An explicit --target argument
always wins, so any launcher can audit either target.

This is an auditor, not a hardening tool. It reads files and reports static residue; it
never launches the browser under audit and never uses the network except for the version
lookup. A clean audit is not proof of safety - see the boundary notice in every response.

MIT.
"@
  Set-Content -LiteralPath (Join-Path $Root 'PORTABLE-README.txt') -Value $note -Encoding UTF8
}
