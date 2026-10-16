#Requires -Version 7.0
<#
.SYNOPSIS
    卸载开机自动登录（Windows 服务 + 旧方案计划任务）。

.NOTES
    删除服务需要管理员权限，脚本会自动请求提权。
    即使 python 已被卸载也能兜底删除（走 sc.exe + 计划任务 cmdlet）。
#>
[CmdletBinding()]
param(
    [string]$Python = '',
    [switch]$KeepLogs
)

$ErrorActionPreference = 'Stop'

# ---- 自动提权 -------------------------------------------------------------
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ''
    Write-Host '  删除服务需要管理员权限，正在弹出 UAC 提示 ...' -ForegroundColor Yellow
    Write-Host '  请在弹出的窗口里点「是」。' -ForegroundColor Yellow
    Write-Host ''
    $pwshExe = (Get-Process -Id $PID).Path
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', ('"{0}"' -f $PSCommandPath))
    if ($Python) { $argList += @('-Python', ('"{0}"' -f $Python)) }
    if ($KeepLogs) { $argList += '-KeepLogs' }
    Start-Process -FilePath $pwshExe -ArgumentList $argList -Verb RunAs
    exit 10
}

$Root   = $PSScriptRoot
$Script = Join-Path $Root 'srun_login.py'
$LogDir = Join-Path $Root 'logs'

Write-Host ''
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host '  卸载：开机自动登录（服务 + 旧计划任务）' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ''

# ---- 定位 python（找不到也能兜底卸载）--------------------------------------
if (-not $Python) {
    $cands = [System.Collections.Generic.List[string]]::new()
    $cands.Add('D:\Python3.14.2\python.exe')
    $py = (Get-Command python -ErrorAction SilentlyContinue).Source
    if ($py -and $py -notmatch 'WindowsApps') { $cands.Add($py) }
    foreach ($v in @('314', '313', '312', '311', '310', '39')) {
        $cands.Add((Join-Path $env:LOCALAPPDATA "Programs\Python\Python$v\python.exe"))
    }
    $Python = $cands | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}

if ($Python -and (Test-Path -LiteralPath $Python) -and (Test-Path -LiteralPath $Script)) {
    & $Python $Script svc-uninstall
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} else {
    # 兜底：python 已被卸载时用系统工具直接删
    Write-Host '未找到 python，改用系统工具兜底卸载 ...' -ForegroundColor Yellow
    $svc = Get-Service -Name 'SRunAutoLogin' -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -ne 'Stopped') {
            Write-Host '  正在停止服务 ...' -ForegroundColor Gray
            Stop-Service -Name 'SRunAutoLogin' -Force -ErrorAction SilentlyContinue
        }
        sc.exe delete SRunAutoLogin | Out-Null
        Write-Host '  服务 SRunAutoLogin 已删除。'
    } else {
        Write-Host '  服务 SRunAutoLogin 未安装。'
    }
    Get-ScheduledTask -TaskName 'SRun.AutoLogin' -ErrorAction SilentlyContinue | ForEach-Object {
        Stop-ScheduledTask -TaskName $_.TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false
        Write-Host "  已移除旧计划任务 $($_.TaskName)。"
    }
}

if (-not $KeepLogs -and (Test-Path -LiteralPath $LogDir)) {
    Remove-Item -LiteralPath $LogDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host '------------------------------------------------------------' -ForegroundColor Green
Write-Host '  已卸载。开机不会再自动登录。' -ForegroundColor Green
if ($KeepLogs) { Write-Host "  日志保留在 $LogDir" -ForegroundColor Gray }
Write-Host '------------------------------------------------------------' -ForegroundColor Green
Write-Host ''

exit 0
