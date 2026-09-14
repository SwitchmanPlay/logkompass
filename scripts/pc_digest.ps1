# Same as pc_digest.sh, for Windows PowerShell.
#   .\scripts\pc_digest.ps1 -Target danya@<public-ip> -Port 2242
param(
  [Parameter(Mandatory = $true)][string]$Target,
  [int]$Port = 2242,
  [string]$Day = (Get-Date).ToUniversalTime().AddDays(-1).ToString("yyyy-MM-dd"),
  [string]$LocalConfig = "config.local.toml"
)

$ErrorActionPreference = "Stop"
$remote = "sudo -u logkompass /opt/logkompass/.venv/bin/logkompass --config /etc/logkompass/config.toml aggregate --day $Day"
ssh -p $Port $Target $remote | Out-File -Encoding utf8 "agg-$Day.json"
logkompass --config $LocalConfig digest --input "agg-$Day.json" --no-store --notify stdout
