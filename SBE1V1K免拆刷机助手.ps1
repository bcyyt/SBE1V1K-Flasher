# ============================================================
#  SBE1V1K (Askey RTQ7300T) 免拆刷机助手  v2.1 全自动版
#  流程: 按住Reset上电 → DHCP option43="askey" 握手 → TFTP送
#        启动器+initramfs → 内存系统上线 → 自动备份(回传救砖包)
#        → 哈希自动核对 → 自动刷写 → 自动验收(等LuCI上线)
#  全程零命令零密码: 自动模式下只需按住Reset插一次电!
#  依据: OpenWrt 论坛 yangzhg 方法 + smzdm 中文教程
# ============================================================

$ErrorActionPreference = "Continue"
[Console]::OutputEncoding = [Text.Encoding]::UTF8
chcp 65001 | Out-Null

$BaseDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$TftpRoot  = Join-Path $BaseDir "tftp-root"
$LauncherFile  = "rtq7300t_boot_auto_upgrade_fw.img"
$InitramfsFile = "initramfs.itb"
$FwRuleDHCP = "SBE1V1K-Flasher-UDP67"
$FwRuleTFTP = "SBE1V1K-Flasher-UDP69"
$NetBackup  = Join-Path $BaseDir "网卡备份.json"
$Phase2File = Join-Path $BaseDir "第二阶段命令.txt"

# 路由器侧执行块(单行, ASCII, 供自动注入与手动粘贴两用)
$Block1Line = 'mkdir -p /tmp/bak && cd /tmp/bak && dd if=/dev/mmcblk0 of=mmc-head-32M.bin bs=1M count=32 && fw_printenv > uboot-env.txt && cat /proc/partitions > partitions.txt && for p in /dev/mmcblk0p*; do s=$(cat /sys/block/mmcblk0/${p##*/}/size 2>/dev/null); [ -n "$s" ] && [ "$s" -lt 65536 ] && dd if=$p of=part-${p##*/}.bin; done && sha256sum * > sha256.txt && tar czf /tmp/sbe1v1k-backup.tar.gz -C /tmp/bak . && tftp -p -l /tmp/sbe1v1k-backup.tar.gz -r sbe1v1k-backup.tar.gz 192.168.1.2 && echo BACKUP-OK'
$Block2aLine = "fw_setenv bootargs 'console=ttyMSM0,115200n8 rootwait root=/dev/mmcblk0p27 cma=256M' && fw_setenv do_boot 'aq_load_fw 0x0; mmc read 0x44000000 0x00014022 0x3800; bootm 0x44000000' && fw_setenv bootcmd 'sleep 3; run do_boot; echo EMMC-FAILED; setenv ipaddr 172.16.252.100; setenv serverip 172.16.252.252; tftpboot 0x80000000 initramfs.itb; bootm 0x80000000' && fw_printenv bootargs bootcmd do_boot && tftp -g -r fw.bin -l /tmp/su.bin 192.168.1.2 && sha256sum /tmp/su.bin > /tmp/su.sha && tftp -p -l /tmp/su.sha -r su.sha 192.168.1.2 && echo HASH-SENT"
$Block2bLine = 'sysupgrade -T /tmp/su.bin && sysupgrade -n -v /tmp/su.bin && echo FLASH-DONE'

function W-IP([string]$ip) { [byte[]]($ip.Split('.') | ForEach-Object { [byte][int]$_ }) }
function New-Opt([byte]$c, [byte[]]$d) { [byte[]]($c, [byte]$d.Length) + $d }

function Read-DHCPOptions([byte[]]$pkt) {
    $h = @{}
    if ($pkt.Length -lt 240) { return $h }
    $i = 240
    while ($i -lt $pkt.Length - 2) {
        $c = $pkt[$i]
        if ($c -eq 0) { $i++; continue }
        if ($c -eq 255) { break }
        $len = $pkt[$i+1]
        if ($len -gt 0) { $h[[int]$c] = $pkt[($i+2)..($i+1+$len)] }
        $i += 2 + $len
    }
    return $h
}

function Make-DHCPReply([byte[]]$pkt, [int]$msgType, [string]$yourIP) {
    $r = [byte[]]::new(240)
    $r[0] = 2; $r[1] = 1; $r[2] = 6; $r[3] = 0
    [Array]::Copy($pkt, 4, $r, 4, 4)
    if (($pkt[10] -band 0x80) -ne 0) { $r[10] = 0x80 }
    $y = W-IP $yourIP; [Array]::Copy($y, 0, $r, 16, 4)
    $s = W-IP "172.16.252.252"; [Array]::Copy($s, 0, $r, 20, 4)
    [Array]::Copy($pkt, 28, $r, 28, 16)
    $r[236] = 99; $r[237] = 130; $r[238] = 83; $r[239] = 99
    $o = [byte[]]::new(0)
    $o += New-Opt 53 ([byte[]]@($msgType))
    $o += New-Opt 1  (W-IP "255.255.0.0")
    $o += New-Opt 54 (W-IP "172.16.252.252")
    $o += New-Opt 51 ([byte[]](0,0,1,44))
    $o += New-Opt 43 ([Text.Encoding]::ASCII.GetBytes("askey"))
    $o += [byte[]](255)
    return $r + $o
}

function Send-TFTPFile {
    param([string]$path, $client, [int]$blksize, [bool]$hadOpts)
    $data = [IO.File]::ReadAllBytes($path)
    $sess = New-Object System.Net.Sockets.UdpClient(0)
    $sess.Connect($client)
    $sess.Client.ReceiveTimeout = 5000
    try {
        if ($hadOpts) {
            $oack = [byte[]](0,6) + [Text.Encoding]::ASCII.GetBytes("blksize`0$blksize`0")
            $sess.Send($oack, $oack.Length) | Out-Null
            $ep0 = New-Object System.Net.IPEndPoint([Net.IPAddress]::Any, 0)
            $r0 = $sess.Receive([ref]$ep0)
            if ($r0.Length -lt 4 -or $r0[1] -ne 4) { throw "OACK未被确认" }
        }
        $pos = 0; $blk = 1
        while ($true) {
            $end = [Math]::Min($pos + $blksize, $data.Length)
            $chunk = if ($pos -lt $data.Length) { $data[$pos..($end-1)] } else { @() }
            $pkt = [byte[]](0,3,($blk -shr 8) -band 0xFF, $blk -band 0xFF) + $chunk
            $sent = $false
            for ($try = 1; $try -le 5 -and -not $sent; $try++) {
                $sess.Send($pkt, $pkt.Length) | Out-Null
                try {
                    $ep = New-Object System.Net.IPEndPoint([Net.IPAddress]::Any, 0)
                    $r = $sess.Receive([ref]$ep)
                    if ($r.Length -ge 4 -and $r[1] -eq 4) {
                        $ackblk = ($r[2] -shl 8) + $r[3]
                        if ($ackblk -eq $blk) { $sent = $true }
                    }
                } catch { }
            }
            if (-not $sent) { throw "块 $blk 重传5次无ACK" }
            $pos += $blksize; $blk++
            if (($blk % 400) -eq 0) {
                Write-Host ("    传输中: {0:N0}/{1:N0} 字节" -f $pos, $data.Length)
            }
            if ($chunk.Count -lt $blksize -and $pos -ge $data.Length) { break }
        }
    } finally { $sess.Close() }
}

function Receive-TFTPFile {
    param($client, [string]$fname, [int]$blksize, [bool]$hadOpts)
    $safe = [IO.Path]::GetFileName($fname)
    if ($safe -notmatch '^[\w.\-]+$') { $safe = "upload.bin" }
    $destDir = Join-Path $BaseDir "backup"
    if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir | Out-Null }
    $dest = Join-Path $destDir "$(Get-Date -Format 'yyyyMMdd-HHmmss')-$safe"
    $sess = New-Object System.Net.Sockets.UdpClient(0)
    $sess.Connect($client)
    $sess.Client.ReceiveTimeout = 90000
    $fs = $null
    try {
        if ($hadOpts) {
            $oack = [byte[]](0,6) + [Text.Encoding]::ASCII.GetBytes("blksize`0$blksize`0")
            $sess.Send($oack, $oack.Length) | Out-Null
        } else {
            $sess.Send([byte[]](0,4,0,0), 4) | Out-Null
        }
        $fs = [System.IO.FileStream]::new($dest, [IO.FileMode]::Create)
        $expect = 1
        $lastP = 0
        while ($true) {
            $ep2 = New-Object System.Net.IPEndPoint([Net.IPAddress]::Any, 0)
            $r = $sess.Receive([ref]$ep2)
            if ($r.Length -lt 4) { continue }
            $op = ($r[0] -shl 8) + $r[1]
            $blk = ($r[2] -shl 8) + $r[3]
            if ($op -ne 3) { continue }
            if ($blk -eq $expect) {
                if ($r.Length -gt 4) {
                    $chunk = $r[4..($r.Length-1)]
                    $fs.Write($chunk, 0, $chunk.Count)
                }
                $expect++
                if (($blk % 800) -eq 0 -and $blk -ne $lastP) {
                    Write-Host ("      回传中... {0:N1} MB" -f ($fs.Length/1MB)) -ForegroundColor DarkGray
                    $lastP = $blk
                }
            }
            $sess.Send([byte[]](0,4,($blk -shr 8) -band 0xFF, $blk -band 0xFF), 4) | Out-Null
            if (($r.Length - 4) -lt $blksize) { break }
        }
        $fs.Close()
        $Script:LastRxName = $safe
        $Script:LastRxPath = $dest
        if ($safe -like '*.tar.gz') {
            Write-Host ("[{0:mm:ss}] [备份] 救砖包已收到: backup\{1} ({2:N1} MB)" -f $sw.Elapsed, (Split-Path -Leaf $dest), ((Get-Item $dest).Length/1MB)) -ForegroundColor Green
        } else {
            Write-Host ("[{0:mm:ss}] [回传] {1} 已收到" -f $sw.Elapsed, $safe) -ForegroundColor Green
        }
    } catch {
        if ($fs) { $fs.Close() }
        Write-Host ("[回传] 接收中断: {0}" -f $_.Exception.Message) -ForegroundColor Red
    } finally { $sess.Close() }
}

function Parse-RRQ([byte[]]$pkt, [ref]$fname, [ref]$blksize, [ref]$hadOpts) {
    if ($pkt.Length -lt 4 -or $pkt[0] -ne 0 -or ($pkt[1] -ne 1 -and $pkt[1] -ne 2)) { return $false }
    $s = [Text.Encoding]::ASCII.GetString($pkt)
    $parts = $s.Substring(2).Split([char]0)
    $fname.Value = $parts[0]
    for ($k = 2; $k -lt $parts.Count - 1; $k += 2) {
        $hadOpts.Value = $true
        if ($parts[$k] -eq "blksize") { $blksize.Value = [Math]::Max(8, [Math]::Min(65464, [int]$parts[$k+1])) }
    }
    return $true
}

# ---------- 自动化: ssh窗口驱动 ----------
$sshProc = $null
function Focus-Ssh {
    if (-not $sshProc) { return $false }
    $ws = New-Object -ComObject WScript.Shell
    for ($i = 0; $i -lt 4; $i++) {
        if ($ws.AppActivate($sshProc.Id)) { Start-Sleep -Milliseconds 300; return $true }
        Start-Sleep -Milliseconds 400
    }
    return $false
}
function Send-SshLine([string]$line) {
    if (-not (Focus-Ssh)) { Write-Host "[自动] 无法聚焦ssh窗口! 请手动粘贴(见第二阶段命令.txt)" -ForegroundColor Red; return $false }
    Set-Clipboard -Value $line
    Start-Sleep -Milliseconds 200
    $ws = New-Object -ComObject WScript.Shell
    $ws.SendKeys("^v")
    Start-Sleep -Milliseconds 300
    $ws.SendKeys("{ENTER}")
    return $true
}

# ---------- 环境检查 ----------
Write-Host "══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "        SBE1V1K 免拆刷机助手 v2.1 全自动版" -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════════════" -ForegroundColor Cyan

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[X] 请右键以管理员身份运行!" -ForegroundColor Red; Read-Host 回车退出; exit 1
}

$launcherPath = Join-Path $TftpRoot $LauncherFile
$initPath = Join-Path $TftpRoot $InitramfsFile
if (-not (Test-Path $launcherPath)) { Write-Host "[X] 缺少 tftp-root\$LauncherFile" -ForegroundColor Red; Read-Host 回车退出; exit 1 }
if (-not (Test-Path $initPath)) { Write-Host "[X] 缺少 tftp-root\$InitramfsFile" -ForegroundColor Red; Read-Host 回车退出; exit 1 }
$initSize = (Get-Item $initPath).Length
if ($initSize -ge 31MB) { Write-Host "[X] initramfs.itb 超过31MB, 原厂U-Boot限制!" -ForegroundColor Red; Read-Host 回车退出; exit 1 }
Write-Host "[OK] 启动器  : $LauncherFile ($((Get-Item $launcherPath).Length) B)"
Write-Host "[OK] 内存系统: $InitramfsFile ($([math]::Round($initSize/1MB,1)) MB)"

$fws = Get-ChildItem (Join-Path $BaseDir "firmware") -Filter *.bin -ErrorAction SilentlyContinue
$fwName = if ($fws) { $fws[0].Name } else { $null }
$fwTftp = Join-Path $TftpRoot "fw.bin"
$fwHash = $null
if ($fws) {
    Copy-Item $fws[0].FullName $fwTftp -Force
    $fwHash = (Get-FileHash $fwTftp -Algorithm SHA256).Hash
    Write-Host "[OK] 待刷固件: firmware\$fwName"
    Write-Host "     SHA256: $fwHash"
} else {
    Write-Host "[!] firmware\ 没有固件! 全自动将停在备份完成这一步" -ForegroundColor Yellow
    Write-Host "    → 现在就去下载 sysupgrade.bin 放进 firmware\ 再回来" -ForegroundColor Yellow
}

# ---------- 模式选择 ----------
Write-Host ""
Write-Host "── 运行模式 ──────────────────────────────────" -ForegroundColor Cyan
Write-Host "  [A] 全自动: 备份→校验→刷写→验收  (推荐, 全程勿动键鼠)" -ForegroundColor White
Write-Host "  [B] 只备份: 备份回传后停住, 不刷写" -ForegroundColor White
Write-Host "  [M] 手动  : 我自己粘贴命令(第三阶段命令见txt)" -ForegroundColor White
$modeSel = Read-Host "选择 (回车=A)"
$AutoMode = "full"
if ($modeSel -ieq 'b') { $AutoMode = "backup" }
elseif ($modeSel -ieq 'm') { $AutoMode = "manual" }
$modeTxt = @{ full = "全自动(备份+刷写)"; backup = "只备份不刷写"; manual = "手动粘贴" }[$AutoMode]
Write-Host "[OK] 模式: $modeTxt" -ForegroundColor Green
if ($AutoMode -eq 'full') {
    Write-Host "     ★ 自动期间请勿碰键盘鼠标(剪贴板会被使用)" -ForegroundColor Magenta
    if (-not $fwHash) { Write-Host "     ★ 没放固件! 自动流程会在备份后暂停等你" -ForegroundColor Magenta }
}

# ---------- 网卡 ----------
Write-Host ""
Write-Host "── 选择与路由器直连的有线网卡 ──" -ForegroundColor Cyan
$nics = Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' -and $_.MediaType -eq '802.3' }
if ($nics.Count -eq 0) { Write-Host "[X] 没有已连接的网卡, 请插好网线再运行" -ForegroundColor Red; Read-Host 回车退出; exit 1 }
for ($i = 0; $i -lt $nics.Count; $i++) {
    Write-Host ("  [{0}] {1}  ({2}, {3})" -f ($i+1), $nics[$i].Name, $nics[$i].InterfaceDescription, $nics[$i].LinkSpeed)
}
$sel = Read-Host "输入序号回车(默认1)"
if ($sel -notmatch '^\d+$' -or [int]$sel -lt 1 -or [int]$sel -gt $nics.Count) { $sel = 1 }
$nicName = $nics[[int]$sel - 1].Name
Write-Host "[OK] 使用网卡: $nicName"

# ---------- 备份+配置网卡 ----------
$ip0 = Get-NetIPAddress -InterfaceAlias $nicName -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
@{ name = $nicName; static = ($ip0 -and $ip0.PrefixOrigin -eq 'Manual'); ip = $ip0.IPAddress; mask = "255.255.255.0"; gw = (Get-NetRoute -InterfaceAlias $nicName -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop } | ConvertTo-Json | Out-File $NetBackup -Encoding utf8
netsh interface ipv4 set address name="$nicName" static 172.16.252.252 255.255.0.0 | Out-Null
netsh interface ipv4 add address name="$nicName" 192.168.1.2 255.255.255.0 | Out-Null
netsh advfirewall firewall add rule name=$FwRuleDHCP dir=in action=allow protocol=UDP localport=67 | Out-Null
netsh advfirewall firewall add rule name=$FwRuleTFTP dir=in action=allow protocol=UDP localport=69 | Out-Null
Write-Host "[OK] 网卡已配置 172.16.252.252 + 192.168.1.2 / 防火墙已放行 UDP67/69"

# ---------- 起服务 ----------
$dhcpSock = $null; $tftpSock = $null
try {
    $dhcpSock = New-Object System.Net.Sockets.UdpClient(67)
    $tftpSock = New-Object System.Net.Sockets.UdpClient(69)
} catch {
    Write-Host "[X] UDP 67/69 被占用: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "    Win+R → services.msc → 停用 Internet Connection Sharing (SharedAccess)" -ForegroundColor Yellow
    Read-Host 回车退出; exit 1
}
$Script:Lease = 10
$Script:SentFiles = 0
$Script:BackupDone = $false
$Script:BackupFile = $null
$Script:HashOK = $false
$Script:LastRxName = $null
$Script:LastRxPath = $null
$Script:Block2Shown = $false
$Script:FlashStarted = $false
$Script:Done80 = $false

Write-Host ""
Write-Host "══════════════════════════════════════════════════" -ForegroundColor Green
Write-Host " 服务已就绪! 现在操作路由器:" -ForegroundColor Green
Write-Host "  1. 网线插路由器 [LAN1] 2.5G口 (10G口不工作!)" -ForegroundColor White
Write-Host "  2. 按住Reset不放 → 接通电源 → 保持约12秒后松手" -ForegroundColor White
if ($AutoMode -eq 'full') {
    Write-Host " 之后全自动: 握手→传系统→备份→核对→刷写→验收" -ForegroundColor Yellow
    Write-Host " 你什么都不用做, 等待完成提示即可" -ForegroundColor Yellow
} else {
    Write-Host " 流程: DHCP握手 → 传启动器 → 传initramfs → 内存系统上线" -ForegroundColor Yellow
}
Write-Host " (RAM启动零风险: 不写eMMC, 断电即回原厂)" -ForegroundColor DarkGray
Write-Host "══════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""

# 自动化状态机
$auto = @{ step = 'idle'; at = (Get-Date) }
function Queue-Step([string]$s, [int]$delaySec) { $auto.step = $s; $auto.at = (Get-Date).AddSeconds($delaySec) }

function Show-Block2 {
    if ($Script:Block2Shown) { return }
    $Script:Block2Shown = $true
    Write-Host ""
    Write-Host "══════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host " [OK] 救砖包已入库! 现在 ssh 窗口粘贴【块2】" -ForegroundColor Magenta
    Write-Host "──────────────────────────────────────────────────"
    Write-Host " $Block2aLine" -ForegroundColor White
    Write-Host " (回传 su.sha 后我会自动核对哈希)" -ForegroundColor DarkGray
}

$phase = 0
$sw = [Diagnostics.Stopwatch]::StartNew()
try {
    while ($true) {
        # DHCP
        if ($dhcpSock.Available -gt 0) {
            $ep = New-Object System.Net.IPEndPoint([Net.IPAddress]::Any, 0)
            $pkt = $dhcpSock.Receive([ref]$ep)
            if ($pkt.Length -gt 240) {
                $opts = Read-DHCPOptions $pkt
                if ($opts.ContainsKey(53)) {
                    $mt = $opts[53][0]
                    if ($mt -eq 1 -or $mt -eq 3) {
                        $ip = "172.16.252.$Script:Lease"
                        if ($mt -eq 1) {
                            $reply = Make-DHCPReply $pkt 2 $ip
                            $dhcpSock.Send($reply, $reply.Length, (New-Object System.Net.IPEndPoint([Net.IPAddress]::Broadcast, 68))) | Out-Null
                            Write-Host ("[{0:mm:ss}] DHCP: 发现恢复模式设备 {1} → 应答OFFER(option43=askey)" -f $sw.Elapsed, $ep.Address) -ForegroundColor Yellow
                        } else {
                            $reply = Make-DHCPReply $pkt 5 $ip
                            $dhcpSock.Send($reply, $reply.Length, (New-Object System.Net.IPEndPoint([Net.IPAddress]::Broadcast, 68))) | Out-Null
                            Write-Host ("[{0:mm:ss}] DHCP: 确认 {1} → ACK" -f $sw.Elapsed, $ip) -ForegroundColor Yellow
                        }
                    }
                }
            }
        }
        # TFTP
        if ($tftpSock.Available -gt 0) {
            $ep = New-Object System.Net.IPEndPoint([Net.IPAddress]::Any, 0)
            $pkt = $tftpSock.Receive([ref]$ep)
            $fname = ""; $bs = 512; $ho = $false
            if ($pkt.Length -ge 2 -and $pkt[1] -eq 2) {
                if (Parse-RRQ $pkt ([ref]$fname) ([ref]$bs) ([ref]$ho)) {
                    Write-Host ("[{0:mm:ss}] TFTP: 设备回传 {1} → 接收中..." -f $sw.Elapsed, $fname) -ForegroundColor Yellow
                    try { Receive-TFTPFile $ep $fname $bs $ho } catch { Write-Host "[回传] 异常: $_" -ForegroundColor Red }
                    if ($Script:LastRxName -eq 'su.sha') {
                        # 哈希核对闸门
                        $rxHash = ((Get-Content $Script:LastRxPath -Raw) -split '\s+')[0]
                        if ($fwHash -and $rxHash -and $rxHash.ToLower() -eq $fwHash.ToLower()) {
                            $Script:HashOK = $true
                            Write-Host "[哈希] ✓ 路由器侧与电脑侧SHA256一致! 固件传输完整" -ForegroundColor Green
                            if ($AutoMode -eq 'full') { Queue-Step 'paste_b2b' 3 }
                            elseif ($AutoMode -eq 'manual') { Write-Host " 手动模式: 现在粘贴块2b: $Block2bLine" -ForegroundColor Magenta }
                        } else {
                            Write-Host "[哈希] ✗✗✗ 不一致! 电脑:$fwHash / 路由器:$rxHash" -ForegroundColor Red
                            Write-Host "       已阻止自动刷写! 请重新执行块2a" -ForegroundColor Red
                        }
                    }
                    elseif ($Script:LastRxName -like '*.tar.gz') {
                        $Script:BackupDone = $true
                        $Script:BackupFile = $Script:LastRxPath
                        Write-Host " ★ 请立刻把 backup\ 里的救砖包另存到U盘/网盘!" -ForegroundColor Magenta
                        if ($AutoMode -eq 'full') {
                            if ($fwHash) { Queue-Step 'paste_b2a' 4 }
                            else { Write-Host "[暂停] firmware\ 没有固件! 放入后手动粘贴块2a(见txt)" -ForegroundColor Yellow }
                        }
                        elseif ($AutoMode -eq 'manual') { Show-Block2 }
                        elseif ($AutoMode -eq 'backup') {
                            Write-Host "[模式B] 备份完成, 按约定停止. 可ESC退出" -ForegroundColor Green
                        }
                    }
                }
            }
            elseif (Parse-RRQ $pkt ([ref]$fname) ([ref]$bs) ([ref]$ho)) {
                $fpath = Join-Path $TftpRoot $fname
                if ((Test-Path $fpath) -and -not $fname.Contains("..")) {
                    $sz = (Get-Item $fpath).Length
                    Write-Host ("[{0:mm:ss}] TFTP: 设备请求 {1} ({2:N0}B) → 传输中..." -f $sw.Elapsed, $fname, $sz) -ForegroundColor Yellow
                    try {
                        Send-TFTPFile $fpath $ep $bs $ho
                        $Script:SentFiles++
                        Write-Host ("[{0:mm:ss}] TFTP: OK {1} 传输完成" -f $sw.Elapsed, $fname) -ForegroundColor Green
                        if ($Script:SentFiles -ge 2 -and $phase -lt 2) {
                            $phase = 2
                            Write-Host "[**] 双文件送达! 内存系统启动中(约60秒)..." -ForegroundColor Magenta
                        }
                    } catch {
                        Write-Host ("[!] {0} 传输中断: {1} (设备会重试)" -f $fname, $_.Exception.Message) -ForegroundColor Red
                    }
                } else {
                    $copied = $false
                    if ($fname -eq "fw.bin") {
                        $fwNow = Get-ChildItem (Join-Path $BaseDir "firmware") -Filter *.bin -ErrorAction SilentlyContinue | Sort-Object { $_.Name -notmatch 'sysupgrade' } | Select-Object -First 1
                        if ($fwNow) {
                            Copy-Item $fwNow.FullName $fpath -Force
                            $fwHash = (Get-FileHash $fpath -Algorithm SHA256).Hash
                            Write-Host "[固件] 检测到固件已放入: $($fwNow.Name)" -ForegroundColor Cyan
                            Write-Host "       SHA256: $fwHash" -ForegroundColor Cyan
                            $copied = $true
                        }
                    }
                    if ($copied) {
                        $sz = (Get-Item $fpath).Length
                        Write-Host ("[{0:mm:ss}] TFTP: 设备请求 {1} ({2:N0}B) → 传输中..." -f $sw.Elapsed, $fname, $sz) -ForegroundColor Yellow
                        try { Send-TFTPFile $fpath $ep $bs $ho; Write-Host ("[{0:mm:ss}] TFTP: OK {1} 传输完成" -f $sw.Elapsed, $fname) -ForegroundColor Green }
                        catch { Write-Host ("[!] {0} 传输中断: {1}" -f $fname, $_.Exception.Message) -ForegroundColor Red }
                    } else {
                        $err = [byte[]](0,5,0,1) + [Text.Encoding]::ASCII.GetBytes("File not found`0")
                        $tftpSock.Send($err, $err.Length, $ep) | Out-Null
                        Write-Host ("[!] 设备请求了不存在的文件: {0}" -f $fname) -ForegroundColor Red
                    }
                }
            }
        }
        # 探测内存系统
        if ($phase -eq 2) {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $iar = $tcp.BeginConnect("192.168.1.1", 22, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(300)) {
                try { $tcp.EndConnect($iar); $phase = 3 } catch { $tcp.Close() }
                if ($phase -eq 3) {
                    $tcp.Close()
                    Write-Host ""
                    Write-Host "══════════════════════════════════════════════════" -ForegroundColor Green
                    Write-Host " [OK] 阶段1完成! 内存系统已在 192.168.1.1 上线" -ForegroundColor Green
                    if ($AutoMode -ne 'manual') {
                        Write-Host " 自动模式: 开启ssh并自动执行备份..." -ForegroundColor Green
                    } else {
                        Write-Host " 已打开ssh窗口(密码空, 回车即进) → 粘贴块1" -ForegroundColor Green
                    }
                    # 写命令文档(手动备用)
                    $cmds = @'
==== SBE1V1K 第二阶段命令 v2.1 (全自动备用/手动用) ====

【块1 · 自动备份】ssh窗口粘贴(纯读取零风险):
mkdir -p /tmp/bak && cd /tmp/bak && dd if=/dev/mmcblk0 of=mmc-head-32M.bin bs=1M count=32 && fw_printenv > uboot-env.txt && cat /proc/partitions > partitions.txt && for p in /dev/mmcblk0p*; do s=$(cat /sys/block/mmcblk0/${p##*/}/size 2>/dev/null); [ -n "$s" ] && [ "$s" -lt 65536 ] && dd if=$p of=part-${p##*/}.bin; done && sha256sum * > sha256.txt && tar czf /tmp/sbe1v1k-backup.tar.gz -C /tmp/bak . && tftp -p -l /tmp/sbe1v1k-backup.tar.gz -r sbe1v1k-backup.tar.gz 192.168.1.2 && echo BACKUP-OK

【块2a · 写引导+拉固件+回传哈希】:
fw_setenv bootargs 'console=ttyMSM0,115200n8 rootwait root=/dev/mmcblk0p27 cma=256M' && fw_setenv do_boot 'aq_load_fw 0x0; mmc read 0x44000000 0x00014022 0x3800; bootm 0x44000000' && fw_setenv bootcmd 'sleep 3; run do_boot; echo EMMC-FAILED; setenv ipaddr 172.16.252.100; setenv serverip 172.16.252.252; tftpboot 0x80000000 initramfs.itb; bootm 0x80000000' && fw_printenv bootargs bootcmd do_boot && tftp -g -r fw.bin -l /tmp/su.bin 192.168.1.2 && sha256sum /tmp/su.bin > /tmp/su.sha && tftp -p -l /tmp/su.sha -r su.sha 192.168.1.2 && echo HASH-SENT

【块2b · 正式刷写】(工具核对哈希一致后才应执行):
sysupgrade -T /tmp/su.bin && sysupgrade -n -v /tmp/su.bin && echo FLASH-DONE

→ 报 Image check failed 时: sysupgrade -F -n -v /tmp/su.bin
→ 之后等150~200秒 → http://192.168.1.1

【块3 · 救砖/恢复原厂】(先备份tar.gz拷入tftp-root\, 走第一步进内存系统):
tftp -g -r sbe1v1k-backup.tar.gz -l /tmp/restore.tar.gz 192.168.1.2
mkdir -p /tmp/restore && tar xzf /tmp/restore.tar.gz -C /tmp/restore
cd /tmp/restore
dd if=mmc-head-32M.bin of=/dev/mmcblk0 bs=1M count=32
for f in part-mmcblk0p*.bin; do dd if=$f of=/dev/${f#part-}; done
sync
'@
                    $cmds | Out-File $Phase2File -Encoding utf8
                    # 开ssh窗口
                    $sshProc = Start-Process cmd -ArgumentList "/k title SBE1V1K-SSH & color 0A & ssh -o StrictHostKeyChecking=no root@192.168.1.1" -PassThru
                    Start-Sleep -Seconds 1
                    if ($AutoMode -ne 'manual') {
                        Queue-Step 'ssh_password' 7
                    } else {
                        Invoke-Item $Phase2File
                    }
                }
            } else { $tcp.Close() }
        }
        # 自动状态机
        if ($AutoMode -ne 'manual' -and $auto.step -ne 'idle' -and (Get-Date) -ge $auto.at) {
            switch ($auto.step) {
                'ssh_password' {
                    Write-Host "[自动] ssh登录(空密码回车)..." -ForegroundColor Cyan
                    if (Focus-Ssh) {
                        $ws = New-Object -ComObject WScript.Shell
                        $ws.SendKeys("{ENTER}")
                        Queue-Step 'paste_b1' 6
                    } else { Queue-Step 'ssh_password' 3 }
                }
                'paste_b1' {
                    Write-Host "[自动] 注入块1: 自动备份(引导区+0:ART校准+小分区)..." -ForegroundColor Cyan
                    if (Send-SshLine $Block1Line) { $auto.step = 'idle' }
                    else { Queue-Step 'paste_b1' 5 }
                }
                'paste_b2a' {
                    Write-Host "[自动] 注入块2a: 写引导参数+拉固件(约1-3分钟)..." -ForegroundColor Cyan
                    if (Send-SshLine $Block2aLine) { $auto.step = 'idle' }
                    else { Queue-Step 'paste_b2a' 5 }
                }
                'paste_b2b' {
                    if (-not $Script:HashOK) { $auto.step = 'idle'; break }
                    Write-Host "[自动] 注入块2b: 正式刷写! (约3分钟, 路由器将自动重启)" -ForegroundColor Magenta
                    if (Send-SshLine $Block2bLine) {
                        $Script:FlashStarted = $true
                        Write-Host "[等待] 刷写中... 之后自动检测新系统上线" -ForegroundColor Cyan
                        Queue-Step 'wait_boot' 60
                    } else { Queue-Step 'paste_b2b' 5 }
                }
                'wait_boot' {
                    $tcp = New-Object System.Net.Sockets.TcpClient
                    $iar = $tcp.BeginConnect("192.168.1.1", 80, $null, $null)
                    if ($iar.AsyncWaitHandle.WaitOne(400)) {
                        try {
                            $tcp.EndConnect($iar); $tcp.Close()
                            $Script:Done80 = $true
                            Write-Host ""
                            Write-Host "══════════════════════════════════════════════════" -ForegroundColor Green
                            Write-Host " 🎉 全自动刷机完成! 新系统已上线" -ForegroundColor Green
                            Write-Host " → 浏览器打开 http://192.168.1.1 设置新密码" -ForegroundColor Green
                            Write-Host " → 首次进入后请配置WAN, 网线可换任意口" -ForegroundColor Green
                            Write-Host " → 本窗口按ESC退出(自动恢复网卡)" -ForegroundColor DarkGray
                            Write-Host "══════════════════════════════════════════════════" -ForegroundColor Green
                            Start-Process "http://192.168.1.1"
                            $auto.step = 'idle'
                        } catch { $tcp.Close(); Queue-Step 'wait_boot' 8 }
                    } else { $tcp.Close(); Queue-Step 'wait_boot' 8 }
                }
            }
        }
        Start-Sleep -Milliseconds 150
        if ($host.UI.RawUI.KeyAvailable) {
            $k = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown,IncludeKeyUp")
            if ($k.KeyDown -and $k.VirtualKeyCode -eq 27) { Write-Host "`n[!] ESC退出, 恢复网卡..."; break }
        }
    }
} finally {
    Write-Host ""
    Write-Host "── 清理与恢复 ──" -ForegroundColor Cyan
    try { $dhcpSock.Close() } catch {}
    try { $tftpSock.Close() } catch {}
    netsh advfirewall firewall delete rule name=$FwRuleDHCP 2>$null | Out-Null
    netsh advfirewall firewall delete rule name=$FwRuleTFTP 2>$null | Out-Null
    netsh interface ipv4 delete address name="$nicName" 192.168.1.2 2>$null | Out-Null
    if (Test-Path $NetBackup) {
        try {
            $b = Get-Content $NetBackup -Raw | ConvertFrom-Json
            if ($b.static -and $b.ip) {
                if ($b.gw) {
                    netsh interface ipv4 set address name="$($b.name)" static $b.ip $b.mask $b.gw | Out-Null
                } else {
                    netsh interface ipv4 set address name="$($b.name)" static $b.ip $b.mask | Out-Null
                }
            } else {
                netsh interface ipv4 set address name="$($b.name)" dhcp | Out-Null
            }
            Write-Host "[OK] 网卡已恢复原配置"
        } catch { Write-Host "[!] 网卡恢复失败, 请手动检查网络设置" -ForegroundColor Red }
    }
    Write-Host "[OK] 防火墙规则已移除, 服务已停止"
    Write-Host "════ 刷机助手退出 ════"
    Read-Host "回车关闭"
}
