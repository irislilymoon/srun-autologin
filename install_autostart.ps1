#Requires -Version 7.0
<#
.SYNOPSIS
    安装「开机早期就完成认证」的 Windows 服务。

.DESCRIPTION
    服务 SRunAutoLogin 以 LocalSystem 运行，开机由服务控制管理器(SCM)直接拉起，
    不依赖任务计划程序的触发时机——与壁纸软件「用户还没登录就已就绪」是同一机制。

    服务进程启动后立刻上报 RUNNING，然后等网络栈就绪并完成深澜认证，
    认证结束（成功/跳过/超时）即退出，不常驻、不重连。
    装完立即启动一次验证，无需重启。旧方案的计划任务会被自动移除。

    需要管理员权限（要创建服务），脚本会自动请求提权。

.EXAMPLE
    pwsh -File .\install_autostart.ps1
#>
[CmdletBinding()]
param(
    [string]$Python = '',
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# ---- 自动提权 -------------------------------------------------------------
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ''
    Write-Host '  创建服务需要管理员权限，正在弹出 UAC 提示 ...' -ForegroundColor Yellow
    Write-Host '  请在弹出的窗口里点「是」。' -ForegroundColor Yellow
    Write-Host ''
    $pwshExe = (Get-Process -Id $PID).Path
    $argList = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit',
        '-File', ('"{0}"' -f $PSCommandPath), '-Force'
    )
    if ($Python) { $argList += @('-Python', ('"{0}"' -f $Python)) }
    Start-Process -FilePath $pwshExe -ArgumentList $argList -Verb RunAs
    exit 10                       # 10 = 已请求提权，真正的安装在另一个窗口里
}

# ---- 路径 -----------------------------------------------------------------
$Root   = $PSScriptRoot
$Script = Join-Path $Root 'srun_login.py'

# ---- 自动探测 python.exe（换电脑不用改脚本）-------------------------------
# 服务用的 pythonw.exe 由 srun_login.py 基于 sys.executable 自动定位，
# 这里只需找到 python.exe。
if (-not $Python) {
    $cands = [System.Collections.Generic.List[string]]::new()
    $cands.Add('D:\Python3.14.2\python.exe')
    $py = (Get-Command python -ErrorAction SilentlyContinue).Source
    if ($py -and $py -notmatch 'WindowsApps') { $cands.Add($py) }   # 跳过微软商店假 python
    foreach ($v in @('314', '313', '312', '311', '310', '39')) {
        $cands.Add((Join-Path $env:LOCALAPPDATA "Programs\Python\Python$v\python.exe"))
    }
    $Python = $cands | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}
if (-not $Python -or -not (Test-Path -LiteralPath $Python)) {
    throw "找不到 python.exe。请显式指定，例如：`n    pwsh -File .\install_autostart.ps1 -Python `"C:\Python313\python.exe`""
}
if (-not (Test-Path -LiteralPath $Script)) {
    throw "找不到 srun_login.py：$Script"
}

Write-Host ''
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host '  安装：开机早期自动登录（Windows 服务方式）' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host '  服务名   : SRunAutoLogin（LocalSystem，开机由 SCM 直接拉起）'
Write-Host "  解释器   : $Python"
Write-Host '  日志     : logs\srun-svc.log'
Write-Host ''
if (-not (Test-Path -LiteralPath (Join-Path $Root 'config.json'))) {
    Write-Warning '没有 config.json，服务启动后会报配置错误。先双击「配置账号密码.bat」。'
}

# ---- 安装（创建服务 + 失败自愈 + 立即启动验证，全在 python 端完成）---------
& $Python $Script svc-install
$rc = $LASTEXITCODE
if ($rc -ne 0) {
    Write-Host ''
    Write-Host "安装失败，退出码 $rc" -ForegroundColor Red
    exit $rc
}

Write-Host ''
Write-Host '提示：下次开机的真实时序，重启后用下面命令复盘 ——'
Write-Host '  python srun_login.py svc-status'
exit 0
