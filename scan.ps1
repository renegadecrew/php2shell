[CmdletBinding()]
param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$CliArgs
)

$ErrorActionPreference = 'Stop'
$NodeBin = if ($env:PHP2SHELL_NODE) { $env:PHP2SHELL_NODE } else { 'node' }
$ScriptPath = Join-Path $PSScriptRoot 'src\cli.js'

& $NodeBin $ScriptPath @CliArgs
exit $LASTEXITCODE
