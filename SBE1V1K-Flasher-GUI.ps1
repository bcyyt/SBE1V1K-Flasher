# ============================================================
#  SBE1V1K (Askey RTQ7300T) 免拆刷机助手  v3.0 图形界面版
#  界面: WinForms (Windows 自带, 零依赖)
#  架构: 引擎跑后台 Runspace(网络全套), UI 线程只做显示与
#        剪贴板/键盘注入/浏览器动作 —— 双向经同步队列通信
#  流程: 按住Reset上电 → DHCP option43="askey" → TFTP双文件
#        → 内存系统 → 自动备份救砖包 → 哈希核对 → 自动刷写
#  依据: OpenWrt 论坛 yangzhg 方法 + smzdm 中文教程
# ============================================================

# ---------- 0. 自提权 ----------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`""
    exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$BaseDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$TftpRoot  = Join-Path $BaseDir "tftp-root"

# ---------- 1. 共享状态(引擎线程与UI线程并发访问, 必须同步包装) ----------
$shared = [hashtable]::Synchronized(@{
    BaseDir = $BaseDir
    Mode = 'auto'; NicName = ''; FirmwarePath = $null
    Stop = $false; Finished = $true; Running = $false
    Step = '待开始'; Progress = 0; Xfer = ''
    BackupFile = $null; HashOK = $false; Success = $false
    SshPid = 0; Blocks = $null; LastRxName = $null; LastRxPath = $null
    Q = [System.Collections.Queue]::Synchronized((New-Object System.Collections.Queue))
})
# 固件自动探测(firmware\*.bin)
$fwAuto = Get-ChildItem (Join-Path $BaseDir "firmware") -Filter *.bin -ErrorAction SilentlyContinue | Select-Object -First 1
if ($fwAuto) { $shared.FirmwarePath = $fwAuto.FullName }

# ---------- 2. 引擎(后台 Runspace 执行) ----------
$engine = @'
param($shared)
$ErrorActionPreference = "Continue"
$BaseDir  = $shared.BaseDir
$TftpRoot = Join-Path $BaseDir "tftp-root"
$FwRuleDHCP = "SBE1V1K-Flasher-UDP67"; $FwRuleTFTP = "SBE1V1K-Flasher-UDP69"
$NetBackup  = Join-Path $BaseDir "网卡备份.json"
$nicName = $shared.NicName

$Block1Line = 'mkdir -p /tmp/bak && cd /tmp/bak && dd if=/dev/mmcblk0 of=mmc-head-32M.bin bs=1M count=32 && fw_printenv > uboot-env.txt && cat /proc/partitions > partitions.txt && for p in /dev/mmcblk0p*; do s=$(cat /sys/block/mmcblk0/${p##*/}/size 2>/dev/null); [ -n "$s" ] && [ "$s" -lt 65536 ] && dd if=$p of=part-${p##*/}.bin; done && sha256sum * > sha256.txt && tar czf /tmp/sbe1v1k-backup.tar.gz -C /tmp/bak . && tftp -p -l /tmp/sbe1v1k-backup.tar.gz -r sbe1v1k-backup.tar.gz 192.168.1.2 && echo BACKUP-OK'
$Block2aLine = "fw_setenv bootargs 'console=ttyMSM0,115200n8 rootwait root=/dev/mmcblk0p27 cma=256M' && fw_setenv do_boot 'mmc read 0x44000000 0x00014022 0x3800; bootm 0x44000000' && fw_setenv bootcmd 'sleep 3; run do_boot; echo EMMC-FAILED; setenv ipaddr 172.16.252.100; setenv serverip 172.16.252.252; tftpboot 0x80000000 initramfs.itb; bootm 0x80000000' && fw_printenv bootargs bootcmd do_boot && tftp -g -r fw.bin -l /tmp/su.bin 192.168.1.2 && sha256sum /tmp/su.bin > /tmp/su.sha && tftp -p -l /tmp/su.sha -r su.sha 192.168.1.2 && echo HASH-SENT"
$Block2bLine = 'sysupgrade -T /tmp/su.bin && sysupgrade -n -v /tmp/su.bin && echo FLASH-DONE'
$shared.Blocks = @{ b1 = $Block1Line; b2a = $Block2aLine; b2b = $Block2bLine }

function Step($t) { $shared.Step = $t }

function W-IP([string]$ip) { [byte[]]($ip.Split('.') | ForEach-Object { [byte][int]$_ }) }
function New-Opt([byte]$c, [byte[]]$d) { [byte[]]($c, [byte]$d.Length) + $d }
function Read-DHCPOptions([byte[]]$pkt) {
    $map = @{}
    if ($pkt.Length -lt 240) { return $map }
    $i = 240
    while ($i -lt $pkt.Length - 3) {
        $code = $pkt[$i]
        if ($code -eq 0) { $i++; continue }
        if ($code -eq 255) { break }
        $len = $pkt[$i+1]
        if ($len -gt 0) { $map[$code] = $pkt[($i+2)..($i+1+$len)] }
        $i += 2 + $len
    }
    return $map
}
function Make-DHCPReply([byte[]]$p, [byte]$msgType) {
    $r = [byte[]]::new(240)
    $r[0] = 2; $r[1] = $p[1]; $r[2] = $p[2]; $r[3] = 0
    [Array]::Copy($p, 4, $r, 4, 4)
    if (($p[10] -band 0x80) -ne 0) { $r[10] = 0x80 }   # 回显广播标志
    [Array]::Copy($p, 28, $r, 28, 16)
    $yi = W-IP "172.16.252.$Script:Lease"; [Array]::Copy($yi, 0, $r, 16, 4)
    $si = W-IP '172.16.252.252'; [Array]::Copy($si, 0, $r, 20, 4)
    $r[236] = 99; $r[237] = 130; $r[238] = 83; $r[239] = 99   # DHCP魔法Cookie(必须!)
    $o = [byte[]]::new(0)
    $o += New-Opt 53  @($msgType)
    $o += New-Opt 1   (W-IP '255.255.0.0')
    $o += New-Opt 54  (W-IP '172.16.252.252')
    $o += New-Opt 51  ([byte[]](0,0,1,44))
    $o += New-Opt 43  ([Text.Encoding]::ASCII.GetBytes('askey'))
    $o += [byte[]](255)
    return $r + $o
}
function Send-TFTPFile($path, $client, [int]$blksize, [bool]$hadOpts, [int]$pBase = -1, [int]$pSpan = 0) {
    $data = [IO.File]::ReadAllBytes($path)
    $fname = [IO.Path]::GetFileName($path)
    $sess = New-Object System.Net.Sockets.UdpClient(0)
    $sess.Connect($client)
    $sess.Client.ReceiveTimeout = 4000
    try {
        if ($hadOpts) {
            $oack = [byte[]](0,6) + [Text.Encoding]::ASCII.GetBytes("blksize`0$blksize`0")
            $sess.Send($oack, $oack.Length) | Out-Null
        }
        $pos = 0; $blk = 1; $retry = 0
        while ($true) {
            $end = $data.Length - 1
            $chunk = if ($pos -le $end) { $data[$pos..$end] } else { @() }
            if ($chunk.Count -gt $blksize) { $chunk = $chunk[0..($blksize-1)] }
            $pkt = [byte[]](0,3,($blk -shr 8) -band 0xFF, $blk -band 0xFF) + $chunk
            $sess.Send($pkt, $pkt.Length) | Out-Null
            try {
                $ep = New-Object System.Net.IPEndPoint([Net.IPAddress]::Any, 0)
                $rp = $sess.Receive([ref]$ep)
                if (($rp[0] -shl 8) + $rp[1] -eq 4 -and (($rp[2] -shl 8) + $rp[3]) -eq $blk) {
                    $pos += $blksize; $blk++; $retry = 0
                    if ($pBase -ge 0 -and ($blk % 100 -eq 0)) {
                        $pct = [int]($pos * 100 / $data.Length); if ($pct -gt 100) { $pct = 100 }
                        $shared.Progress = $pBase + [int]($pSpan * $pct / 100)
                        $shared.Xfer = "$fname $pct%"
                    }
                } else { $retry++ }
            } catch { $retry++ }
            if ($retry -gt 6) { throw "$fname 重传超时" }
            if ($pos -ge $data.Length -and $chunk.Count -lt $blksize) { break }
        }
    } finally { $sess.Close() }
}
function Receive-TFTPFile($client, [string]$fname, [int]$blksize, [bool]$hadOpts) {
    $safe = [IO.Path]::GetFileName($fname)
    if ($safe -notmatch '^[\w.\-]+$') { $safe = "upload.bin" }
    $destDir = Join-Path $BaseDir "backup"
    if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir | Out-Null }
    $dest = Join-Path $destDir "$(Get-Date -Format 'yyyyMMdd-HHmmss')-$safe"
    $sess = New-Object System.Net.Sockets.UdpClient(0)
    $sess.Connect($client)
    $sess.Client.ReceiveTimeout = 60000
    $fs = $null
    try {
        if ($hadOpts) {
            $oack = [byte[]](0,6) + [Text.Encoding]::ASCII.GetBytes("blksize`0$blksize`0")
            $sess.Send($oack, $oack.Length) | Out-Null
        } else { $sess.Send([byte[]](0,4,0,0), 4) | Out-Null }
        $fs = [System.IO.FileStream]::new($dest, [IO.FileMode]::Create)
        $expect = 1; $lastP = 0
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
                if (($blk % 800) -eq 0 -and $blk -ne $lastP) { $lastP = $blk; $shared.Xfer = "$safe $([math]::Round($fs.Length/1MB,1))MB" }
            }
            $sess.Send([byte[]](0,4,($blk -shr 8) -band 0xFF, $blk -band 0xFF), 4) | Out-Null
            if (($r.Length - 4) -lt $blksize) { break }
        }
        $fs.Close()
        Write-Host "[备份] 救砖包已保存: backup\$(Split-Path -Leaf $dest) ($([math]::Round((Get-Item $dest).Length/1MB,1))MB)"
        $shared.LastRxName = $safe; $shared.LastRxPath = $dest
    } catch {
        if ($fs) { $fs.Close() }
        Write-Host "[备份] 接收中断: $($_.Exception.Message)"
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

# ---------- 主流程 ----------
$AutoMode = $shared.Mode   # auto / backup / manual
$fwHash = $null
try {
    Write-Host "[OK] 引擎启动 | 模式=$AutoMode | 网卡=$nicName"

    # 固件准备
    $fwPath = $null
    if ($shared.FirmwarePath -and (Test-Path $shared.FirmwarePath)) { $fwPath = $shared.FirmwarePath }
    else {
        $fwAuto = Get-ChildItem (Join-Path $BaseDir "firmware") -Filter *.bin -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($fwAuto) { $fwPath = $fwAuto.FullName }
    }
    if ($AutoMode -eq 'auto' -and -not $fwPath) {
        throw "firmware\ 没有固件! 先在界面选择 sysupgrade 固件再开始"
    }
    if ($fwPath) {
        Copy-Item $fwPath (Join-Path $TftpRoot "fw.bin") -Force
        $fwHash = (Get-FileHash (Join-Path $TftpRoot "fw.bin") -Algorithm SHA256).Hash
        Write-Host "[固件] $(Split-Path -Leaf $fwPath) → tftp-root\fw.bin"
        Write-Host "[固件] SHA256: $fwHash"
    }

    # 文件检查
    $launcherPath = Join-Path $TftpRoot 'rtq7300t_boot_auto_upgrade_fw.img'
    $initPath     = Join-Path $TftpRoot 'initramfs.itb'
    if (-not (Test-Path $launcherPath)) { throw "缺 tftp-root\rtq7300t_boot_auto_upgrade_fw.img" }
    if (-not (Test-Path $initPath)) { throw "缺 tftp-root\initramfs.itb" }
    if ((Get-Item $initPath).Length -ge 31MB) { throw "initramfs.itb 超过31MB(原厂U-Boot限制)" }

    # 网卡配置
    Write-Host "[网卡] 备份并配置 $nicName ..."
    $ip0 = Get-NetIPAddress -InterfaceAlias $nicName -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.PrefixOrigin -ne 'WellKnown' } | Select-Object -First 1
    $gw0 = (Get-NetRoute -InterfaceAlias $nicName -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop
    @{ name = $nicName; static = ($null -ne $ip0 -and $ip0.PrefixOrigin -eq 'Manual'); ip = $ip0.IPAddress; mask = $ip0.PrefixLength; gw = $gw0 } | ConvertTo-Json | Out-File $NetBackup -Encoding utf8
    netsh interface ipv4 set address name="$nicName" static 172.16.252.252 255.255.0.0 | Out-Null
    netsh interface ipv4 add address name="$nicName" 192.168.1.2 255.255.255.0 | Out-Null
    netsh advfirewall firewall add rule name=$FwRuleDHCP dir=in action=allow protocol=UDP localport=67 | Out-Null
    netsh advfirewall firewall add rule name=$FwRuleTFTP dir=in action=allow protocol=UDP localport=69 | Out-Null
    Write-Host "[OK] 网卡已配置(172.16.252.252 + 192.168.1.2) 防火墙已放行"

    # 起服务
    try {
        $dhcpSock = New-Object System.Net.Sockets.UdpClient(67)
        $tftpSock = New-Object System.Net.Sockets.UdpClient(69)
    } catch { throw "UDP 67/69 被占用: $($_.Exception.Message) (停用 ICS/SharedAccess 服务后重试)" }
    $Script:Lease = 10; $Script:SentFiles = 0
    $Script:LastRxName = $null; $Script:LastRxPath = $null
    $BackupDone = $false; $HashOK = $false
    Step '等待设备(按住Reset上电)'
    $shared.Progress = 2
    Write-Host "[提示] 网线插路由器LAN1(2.5G口)! 按住Reset不放→插电→12秒后松手"

    $phase = 0
    $autoStep = 'idle'; $autoAt = [DateTime]::Now
    function Queue-Step($s, $delaySec) { $autoStep = $s; $autoAt = [DateTime]::Now.AddSeconds($delaySec) }
    function Push-UI($a, $k, $t) { $shared.Q.Enqueue(@{ a = $a; k = $k; t = $t }) }
    function Focus-Ready { return ($shared.SshPid -gt 0) }

    while ($true) {
        if ($shared.Stop) { break }
        # ---- DHCP ----
        if ($dhcpSock.Available -gt 0) {
            $ep = New-Object System.Net.IPEndPoint([Net.IPAddress]::Any, 0)
            $p = $dhcpSock.Receive([ref]$ep)
            $opts = Read-DHCPOptions $p
            if ($opts.ContainsKey(53)) {
                $mt = $opts[53][0]
                if ($mt -eq 1) {
                    $rep = Make-DHCPReply $p 2
                    $dhcpSock.Send($rep, $rep.Length, (New-Object System.Net.IPEndPoint([Net.IPAddress]::Broadcast, 68))) | Out-Null
                    Step 'DHCP握手'; $shared.Progress = 5
                    Write-Host ("[DHCP] 发现恢复模式设备 ({0}) → 已应答askey" -f $ep.Address)
                } elseif ($mt -eq 3) {
                    $rep = Make-DHCPReply $p 5
                    $dhcpSock.Send($rep, $rep.Length, (New-Object System.Net.IPEndPoint([Net.IPAddress]::Broadcast, 68))) | Out-Null
                    Write-Host "[DHCP] 设备已接受地址 (askey握手成功!)"
                }
            }
        }
        # ---- TFTP ----
        if ($tftpSock.Available -gt 0) {
            $ep = New-Object System.Net.IPEndPoint([Net.IPAddress]::Any, 0)
            $pkt = $tftpSock.Receive([ref]$ep)
            $fname = ""; $bs = 512; $ho = $false
            if ($pkt.Length -ge 2 -and $pkt[1] -eq 2) {
                if (Parse-RRQ $pkt ([ref]$fname) ([ref]$bs) ([ref]$ho)) {
                    Write-Host "[TFTP] 设备回传 $fname → 接收中..."
                    Step '接收备份'
                    $shared.LastRxName = $null; $shared.LastRxPath = $null   # 防残留误触发
                    try { Receive-TFTPFile $ep $fname $bs $ho } catch { Write-Host "[备份] 异常: $_" }
                    if ($shared.LastRxName -eq 'su.sha') {
                        $rxHash = ((Get-Content $shared.LastRxPath -Raw) -split '\s+')[0]
                        if ($fwHash -and $rxHash.ToLower() -eq $fwHash.ToLower()) {
                            $HashOK = $true; $shared.HashOK = $true
                            Write-Host "[校验] 固件SHA256一致 ✓ ($rxHash)"
                            if ($AutoMode -eq 'auto') { Step '刷写中'; $shared.Progress = 85; Queue-Step 'paste_b2b' 2 }
                            elseif ($AutoMode -eq 'manual') { Write-Host "[手动] 校验OK → 现在可以粘贴 块2b 刷写了" }
                        } else {
                            Write-Host "[校验] 固件哈希不一致!! 电脑=$fwHash 路由器=$rxHash —— 已熔断, 不刷!" 
                            Step '哈希不符已中止'
                            $autoStep = 'idle'
                        }
                    } elseif ($shared.LastRxName) {
                        $BackupDone = $true; $shared.BackupFile = $shared.LastRxPath
                        Write-Host "[OK] 救砖包已入库! 文件: $($shared.LastRxPath)"
                        Write-Host "[OK] 请将 backup\ 里的备份另存到U盘/网盘 (0:ART校准数据不可再生)"
                        if ($AutoMode -eq 'backup') {
                            Step '备份完成(已按要求停止)'; $shared.Progress = 100
                            Write-Host "[OK] 只备份模式完成, 不会刷写. 可关闭本工具."
                            $autoStep = 'idle'
                        } elseif ($AutoMode -eq 'auto' -and $fwHash) {
                            Step '写引导+拉固件'; $shared.Progress = 62
                            Queue-Step 'paste_b2a' 3
                        } elseif ($AutoMode -eq 'manual') {
                            Step '备份完成→手动粘贴块2a'
                        }
                    }
                }
            }
            elseif (Parse-RRQ $pkt ([ref]$fname) ([ref]$bs) ([ref]$ho)) {
                $fpath = Join-Path $TftpRoot $fname
                if ((Test-Path $fpath) -and -not $fname.Contains("..")) {
                    $isInit = ($fname -eq 'initramfs.itb')
                    $pb = 8; $ps2 = 32
                    if ($fname -eq 'fw.bin') { $pb = 62; $ps2 = 18 }
                    Write-Host "[TFTP] 设备请求 $fname → 传输中..."
                    try {
                        Send-TFTPFile $fpath $ep $bs $ho $pb $ps2
                        $Script:SentFiles++
                        if ($isInit) {
                            Step '内存系统启动中'; $shared.Progress = 45
                            Write-Host "[TFTP] initramfs 送达! 系统启动约60秒..."
                            $phase = 2
                        }
                    } catch { Write-Host "[TFTP] $fname 传输中断: $($_.Exception.Message) (设备会重试)" }
                } else {
                    $copied = $false
                    if ($fname -eq 'fw.bin' -and -not $fwPath) {
                        $fwNow = Get-ChildItem (Join-Path $BaseDir "firmware") -Filter *.bin -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($shared.FirmwarePath -and (Test-Path $shared.FirmwarePath)) { $fwNow = Get-Item $shared.FirmwarePath }
                        if ($fwNow) {
                            Copy-Item $fwNow.FullName $fpath -Force
                            $fwHash = (Get-FileHash $fpath -Algorithm SHA256).Hash
                            Write-Host "[固件] 检测到固件: $($fwNow.Name) SHA256: $fwHash"
                            $copied = $true
                        }
                    }
                    if ($copied) {
                        try { Send-TFTPFile $fpath $ep $bs $ho 62 18 } catch { Write-Host "[TFTP] fw.bin 传输中断: $($_.Exception.Message)" }
                    } else {
                        $err = [byte[]](0,5,0,1) + [Text.Encoding]::ASCII.GetBytes("File not found`0")
                        $tftpSock.Send($err, $err.Length, $ep) | Out-Null
                        Write-Host "[TFTP] 设备请求了不存在的文件: $fname"
                    }
                }
            }
        }
        # ---- 内存系统探测 ----
        if ($phase -eq 2) {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $iar = $tcp.BeginConnect("192.168.1.1", 22, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(300)) {
                try { $tcp.EndConnect($iar); $phase = 3 } catch { $tcp.Close() }
                if ($phase -eq 3) {
                    $tcp.Close()
                    Step '内存系统已上线'
                    $shared.Progress = 50
                    Write-Host "[OK] 内存系统上线! 192.168.1.1 (root空密码)"
                    $p = Start-Process cmd -ArgumentList "/k title SBE1V1K-SSH & color 0A & ssh -o StrictHostKeyChecking=no root@192.168.1.1" -PassThru
                    $shared.SshPid = $p.Id
                    Write-Host "[OK] ssh窗口已打开 (PID $($p.Id))"
                    if ($AutoMode -eq 'manual') {
                        Write-Host "[手动] 在ssh窗口粘贴: 第二阶段命令.txt 里的块1"
                    } else {
                        Queue-Step 'ssh_password' 7
                    }
                }
            } else { $tcp.Close() }
        }
        # ---- 自动状态机(动作由UI线程执行) ----
        if ($AutoMode -ne 'manual' -and $autoStep -ne 'idle' -and [DateTime]::Now -ge $autoAt) {
            switch ($autoStep) {
                'ssh_password' {
                    Write-Host "[自动] ssh登录(空密码回车)..."
                    Push-UI 'focus' $null $null
                    Push-UI 'keys' '{ENTER}' $null
                    Queue-Step 'paste_b1' 6
                }
                'paste_b1' {
                    Write-Host "[自动] 注入块1: 自动备份(引导链+0:ART校准+小分区)..."
                    Push-UI 'focus' $null $null
                    Push-UI 'paste' $Block1Line $null
                    $autoStep = 'idle'
                }
                'paste_b2a' {
                    Write-Host "[自动] 注入块2a: 写引导参数+拉固件+回传哈希..."
                    Push-UI 'focus' $null $null
                    Push-UI 'paste' $Block2aLine $null
                    $autoStep = 'idle'
                }
                'paste_b2b' {
                    Write-Host "[自动] 哈希核对通过! 注入块2b: sysupgrade 刷写..."
                    Push-UI 'focus' $null $null
                    Push-UI 'paste' $Block2bLine $null
                    $autoStep = 'idle'
                    $script:WaitBoot = $true
                    $script:BootCheckAt = [DateTime]::Now.AddSeconds(60)
                    $script:BootAnnounced = $false
                }
            }
        }
        # ---- 刷写后验收 ----
        if ($script:WaitBoot -and [DateTime]::Now -ge $script:BootCheckAt) {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $iar = $tcp.BeginConnect("192.168.1.1", 80, $null, $null)
            $up = $false
            if ($iar.AsyncWaitHandle.WaitOne(400)) {
                try { $tcp.EndConnect($iar); $up = $true } catch {}
            }
            $tcp.Close()
            if ($up) {
                $script:WaitBoot = $false
                Step '刷机完成!'
                $shared.Progress = 100
                $shared.Success = $true
                Write-Host "[OK] 新系统LuCI已上线! 正在打开浏览器..."
                Push-UI 'openurl' 'http://192.168.1.1' $null
                Write-Host "[OK] 全流程完成! 关闭本工具会自动恢复电脑网卡"
                $autoStep = 'idle'
            } else {
                if (-not $script:BootAnnounced) { $script:BootAnnounced = $true; Write-Host "[等待] sysupgrade刷写中, 新系统上线约需3分钟..." }
                $shared.Progress = 88
                $script:BootCheckAt = [DateTime]::Now.AddSeconds(8)
            }
        }
        Start-Sleep -Milliseconds 150
    }
    if ($shared.Stop) { Write-Host "[停止] 收到停止请求, 正在恢复..." }
} catch {
    Write-Host "[错误] $($_.Exception.Message)"
} finally {
    # 恢复网卡与防火墙
    try { $dhcpSock.Close() } catch {}
    try { $tftpSock.Close() } catch {}
    netsh advfirewall firewall delete rule name=$FwRuleDHCP 2>$null | Out-Null
    netsh advfirewall firewall delete rule name=$FwRuleTFTP 2>$null | Out-Null
    netsh interface ipv4 delete address name="$nicName" 192.168.1.2 2>$null | Out-Null
    if (Test-Path $NetBackup) {
        try {
            $b = Get-Content $NetBackup -Raw | ConvertFrom-Json
            if ($b.static -and $b.ip) {
                if ($b.gw) { netsh interface ipv4 set address name="$($b.name)" static $b.ip $b.mask $b.gw | Out-Null }
                else { netsh interface ipv4 set address name="$($b.name)" static $b.ip $b.mask | Out-Null }
            } else { netsh interface ipv4 set address name="$($b.name)" dhcp | Out-Null }
            Write-Host "[OK] 网卡已恢复原配置"
        } catch { Write-Host "[!] 网卡恢复失败, 请手动检查网络设置" }
    }
    Write-Host "[OK] 防火墙规则已清理"
    $shared.Finished = $true
    $shared.Running = $false
}
'@

# ---------- 3. GUI ----------
$form = New-Object System.Windows.Forms.Form
$form.Text = 'SBE1V1K 免拆刷机助手 v3.0'
$form.Size = New-Object System.Drawing.Size(760, 640)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedSingle'
$form.MaximizeBox = $false
$form.Font = New-Object System.Drawing.Font('Microsoft YaHei UI', 9)

# 模式
$gMode = New-Object System.Windows.Forms.GroupBox
$gMode.Text = '模式'; $gMode.Bounds = '12,12,440,58'
$rbAuto = New-Object System.Windows.Forms.RadioButton
$rbAuto.Text = '全自动刷机(推荐)'; $rbAuto.Bounds = '12,24,130,24'; $rbAuto.Checked = $true
$rbBackup = New-Object System.Windows.Forms.RadioButton
$rbBackup.Text = '只备份不刷写'; $rbBackup.Bounds = '150,24,110,24'
$rbManual = New-Object System.Windows.Forms.RadioButton
$rbManual.Text = '手动粘贴'; $rbManual.Bounds = '268,24,90,24'
$gMode.Controls.AddRange(@($rbAuto, $rbBackup, $rbManual))
$form.Controls.Add($gMode)

# 网卡选择
$gNic = New-Object System.Windows.Forms.GroupBox
$gNic.Text = '网卡(选与路由器直连的有线网卡)'; $gNic.Bounds = '12,76,440,58'
$cbNic = New-Object System.Windows.Forms.ComboBox
$cbNic.Bounds = '12,24,300,24'; $cbNic.DropDownStyle = 'DropDownList'
$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Text = '刷新'; $btnRefresh.Bounds = '320,22,60,26'
$gNic.Controls.AddRange(@($cbNic, $btnRefresh))
$form.Controls.Add($gNic)

function Load-Nics {
    $cbNic.Items.Clear()
    $nics = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }
    foreach ($n in $nics) { [void]$cbNic.Items.Add("$($n.Name) | $($n.LinkSpeed) | $($n.InterfaceDescription)") }
    if ($cbNic.Items.Count -gt 0) { $cbNic.SelectedIndex = 0 }
}
$btnRefresh.Add_Click({ Load-Nics })
Load-Nics

# 固件
$gFw = New-Object System.Windows.Forms.GroupBox
$gFw.Text = '固件(sysupgrade.bin, Releases下载)'; $gFw.Bounds = '12,140,730,58'
$lblFw = New-Object System.Windows.Forms.Label
$lblFw.Bounds = '12,24,600,24'; $lblFw.AutoEllipsis = $true
if ($shared.FirmwarePath) { $lblFw.Text = "已选: $(Split-Path -Leaf $shared.FirmwarePath)" } else { $lblFw.Text = '未选择(firmware\ 目录自动探测, 或点右边选择)' }
$btnFw = New-Object System.Windows.Forms.Button
$btnFw.Text = '选择固件...'; $btnFw.Bounds = '630,20,90,26'
$btnFw.Add_Click({
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Filter = '固件 (*.bin)|*.bin'
    if ($ofd.ShowDialog() -eq 'OK') {
        $shared.FirmwarePath = $ofd.FileName
        $lblFw.Text = "已选: $(Split-Path -Leaf $ofd.FileName)"
    }
})
$gFw.Controls.AddRange(@($lblFw, $btnFw))
$form.Controls.Add($gFw)

# 手动块复制
$gBlocks = New-Object System.Windows.Forms.GroupBox
$gBlocks.Text = '手动模式命令(点击复制, 粘贴到ssh窗口)'; $gBlocks.Bounds = '460,12,282,122'
$b1 = New-Object System.Windows.Forms.Button; $b1.Text = '复制 块1 备份'; $b1.Bounds = '12,22,120,28'
$b2 = New-Object System.Windows.Forms.Button; $b2.Text = '复制 块2a 引导+固件'; $b2.Bounds = '142,22,128,28'
$b3 = New-Object System.Windows.Forms.Button; $b3.Text = '复制 块2b 刷写'; $b3.Bounds = '12,56,120,28'
$b4 = New-Object System.Windows.Forms.Button; $b4.Text = '打开命令文件'; $b4.Bounds = '142,56,128,28'
$lblBlocks = New-Object System.Windows.Forms.Label
$lblBlocks.Text = '块1→等回传→块2a→等[校验OK]→块2b'; $lblBlocks.Bounds = '12,88,258,22'; $lblBlocks.ForeColor = 'DimGray'
foreach ($x in @($b1, $b2, $b3, $b4)) { $gBlocks.Controls.Add($x) }
$gBlocks.Controls.Add($lblBlocks)
$form.Controls.Add($gBlocks)
$b1.Add_Click({ if ($shared.Blocks) { [System.Windows.Forms.Clipboard]::SetText($shared.Blocks.b1); $lblBlocks.Text = '块1 已复制 → 粘贴到ssh窗口' } })
$b2.Add_Click({ if ($shared.Blocks) { [System.Windows.Forms.Clipboard]::SetText($shared.Blocks.b2a); $lblBlocks.Text = '块2a 已复制 → 粘贴到ssh窗口' } })
$b3.Add_Click({ if ($shared.Blocks) { [System.Windows.Forms.Clipboard]::SetText($shared.Blocks.b2b); $lblBlocks.Text = '块2b 已复制 → 确认校验OK后粘贴!' } })
$b4.Add_Click({ $p = Join-Path $BaseDir '第二阶段命令.txt'; if (Test-Path $p) { Start-Process notepad $p } })

# 状态与进度
$gStat = New-Object System.Windows.Forms.GroupBox
$gStat.Text = '状态'; $gStat.Bounds = '12,204,730,84'
$lblStep = New-Object System.Windows.Forms.Label
$lblStep.Text = '待开始'; $lblStep.Bounds = '12,22,500,26'; $lblStep.Font = New-Object System.Drawing.Font('Microsoft YaHei UI', 11, [System.Drawing.FontStyle]::Bold)
$lblXfer = New-Object System.Windows.Forms.Label
$lblXfer.Text = ''; $lblXfer.Bounds = '520,24,200,22'; $lblXfer.ForeColor = 'DimGray'
$pbar = New-Object System.Windows.Forms.ProgressBar
$pbar.Bounds = '12,52,706,22'
$gStat.Controls.AddRange(@($lblStep, $lblXfer, $pbar))
$form.Controls.Add($gStat)

# 日志
$gLog = New-Object System.Windows.Forms.GroupBox
$gLog.Text = '日志'; $gLog.Bounds = '12,296,730,240'
$rtb = New-Object System.Windows.Forms.RichTextBox
$rtb.Bounds = '12,22,706,210'; $rtb.ReadOnly = $true; $rtb.Font = New-Object System.Drawing.Font('Consolas', 9); $rtb.BackColor = [System.Drawing.Color]::FromArgb(245,245,245)
$gLog.Controls.Add($rtb)
$form.Controls.Add($gLog)

# 按钮
$btnStart = New-Object System.Windows.Forms.Button
$btnStart.Text = '开 始'; $btnStart.Bounds = '12,548,180,44'
$btnStart.Font = New-Object System.Drawing.Font('Microsoft YaHei UI', 11, [System.Drawing.FontStyle]::Bold)
$btnStart.BackColor = [System.Drawing.Color]::FromArgb(0,150,80); $btnStart.ForeColor = 'White'; $btnStart.FlatStyle = 'Flat'
$btnStop = New-Object System.Windows.Forms.Button
$btnStop.Text = '停 止'; $btnStop.Bounds = '204,548,120,44'
$btnStop.Enabled = $false
$btnStop.Font = New-Object System.Drawing.Font('Microsoft YaHei UI', 11, [System.Drawing.FontStyle]::Bold)
$btnLink = New-Object System.Windows.Forms.LinkLabel
$btnLink.Text = '打开 Releases 下载固件'; $btnLink.Bounds = '350,560,180,24'
$btnLink.Add_Click({ Start-Process 'https://github.com/bcyyt/OpenWRT-CI/releases' })
$lblHint = New-Object System.Windows.Forms.Label
$lblHint.Text = '全自动期间请勿动键盘鼠标'; $lblHint.Bounds = '350,584,380,20'; $lblHint.ForeColor = 'Firebrick'
$form.Controls.AddRange(@($btnStart, $btnStop, $btnLink, $lblHint))

function Log-Append([string]$msg) {
    $color = [System.Drawing.Color]::Black
    if ($msg -match '^\[(OK|固件|校验)\]|BACKUP-OK|HASH-SENT|FLASH-DONE') { $color = [System.Drawing.Color]::Green }
    elseif ($msg -match '^\[(错误|停止|!)\]|哈希不一致') { $color = [System.Drawing.Color]::Firebrick }
    elseif ($msg -match '^\[(自动|DHCP|TFTP|备份|提示|等待|手动)\]') { $color = [System.Drawing.Color]::RoyalBlue }
    $rtb.SelectionStart = $rtb.Text.Length; $rtb.SelectionLength = 0
    $rtb.SelectionColor = $color
    $rtb.AppendText("$(Get-Date -Format HH:mm:ss) $msg`r`n")
    $rtb.SelectionStart = $rtb.Text.Length
    $rtb.ScrollToCaret()
}

$script:ps = $null
$btnStart.Add_Click({
    if ($cbNic.SelectedIndex -lt 0) { [void][System.Windows.Forms.MessageBox]::Show('请先选择网卡', '提示'); return }
    $nicItem = $cbNic.SelectedItem.ToString()
    $shared.NicName = $nicItem.Split('|')[0].Trim()
    $shared.Mode = if ($rbAuto.Checked) { 'auto' } elseif ($rbBackup.Checked) { 'backup' } else { 'manual' }
    # 重新扫描固件目录(用户可能启动后才放固件)
    if (-not $shared.FirmwarePath -or -not (Test-Path $shared.FirmwarePath)) {
        $fwRe = Get-ChildItem (Join-Path $BaseDir "firmware") -Filter *.bin -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($fwRe) { $shared.FirmwarePath = $fwRe.FullName; $lblFw.Text = "已选: $($fwRe.Name)" }
    }
    if ($shared.Mode -eq 'auto' -and -not $shared.FirmwarePath) {
        [void][System.Windows.Forms.MessageBox]::Show('全自动模式需要固件! 请先点「选择固件」或放入 firmware\ 目录', '提示')
        return
    }
    $shared.Stop = $false; $shared.Finished = $false; $shared.Running = $true
    $shared.Progress = 0; $shared.Success = $false
    $rtb.Clear()
    Log-Append "[界面] 模式=$($shared.Mode) 网卡=$($shared.NicName)"
    if ($shared.Mode -eq 'auto') { Log-Append '[界面] 现在请: 网线插LAN1(2.5G) → 按住Reset插电 → 12秒后松手' }
    $script:ps = [powershell]::Create()
    [void]$script:ps.AddScript($engine)
    [void]$script:ps.AddParameter('shared', $shared)
    [void]$script:ps.BeginInvoke()
    $btnStart.Enabled = $false; $btnStop.Enabled = $true
    $rbAuto.Enabled = $false; $rbBackup.Enabled = $false; $rbManual.Enabled = $false; $cbNic.Enabled = $false; $btnFw.Enabled = $false
})
$btnStop.Add_Click({
    $shared.Stop = $true
    Log-Append '[界面] 已请求停止, 引擎将恢复网卡后退出...'
    $btnStop.Enabled = $false
})
$form.Add_FormClosing({
    if ($shared.Running -and -not $shared.Finished) {
        $r = [System.Windows.Forms.MessageBox]::Show('刷机进行中! 停止将自动恢复网卡, 确定退出?', '确认', 'YesNo', 'Warning')
        if ($r -ne 'Yes') { $_.Cancel = $true; return }
        $shared.Stop = $true
        $deadline = [DateTime]::Now.AddSeconds(6)
        while (-not $shared.Finished -and [DateTime]::Now -lt $deadline) { Start-Sleep -Milliseconds 200 }
        if (-not $shared.Finished) { [void][System.Windows.Forms.MessageBox]::Show('引擎未及时退出, 网卡可能需手动恢复(重新打开本工具再停止一次即可)', '提示') }
    }
})

# UI 定时器
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 200
$timer.Add_Tick({
    if ($script:ps) {
        # 引擎日志
        foreach ($rec in @($script:ps.Streams.Information.ReadAll())) { Log-Append "$($rec.MessageData)" }
        foreach ($err in @($script:ps.Streams.Error.ReadAll())) { Log-Append "[错误] $($err.Exception.Message)" }
        # UI 动作队列
        while ($shared.Q.Count -gt 0) {
            $ev = $shared.Q.Dequeue()
            try {
                if ($ev.a -eq 'focus' -and $shared.SshPid -gt 0) {
                    $ws = New-Object -ComObject WScript.Shell
                    [void]$ws.AppActivate($shared.SshPid)
                    Start-Sleep -Milliseconds 250
                }
                elseif ($ev.a -eq 'keys') {
                    [System.Windows.Forms.SendKeys]::SendWait($ev.k)
                }
                elseif ($ev.a -eq 'paste') {
                    [System.Windows.Forms.Clipboard]::SetText($ev.t)
                    [System.Windows.Forms.SendKeys]::SendWait('^v')
                    Start-Sleep -Milliseconds 150
                    [System.Windows.Forms.SendKeys]::SendWait('{ENTER}')
                }
                elseif ($ev.a -eq 'openurl') { Start-Process $ev.k }
            } catch { Log-Append "[界面] 动作执行异常: $($_.Exception.Message)" }
        }
        # 状态刷新
        $lblStep.Text = $shared.Step
        $lblXfer.Text = $shared.Xfer
        if ($pbar.Value -ne [int]$shared.Progress) { $pbar.Value = [Math]::Min(100, [Math]::Max(0, [int]$shared.Progress)) }
        if ($shared.Finished -and $shared.Running -eq $false) {
            try { $script:ps.Dispose() } catch {}
            $script:ps = $null
            $btnStart.Enabled = $true; $btnStop.Enabled = $false
            $rbAuto.Enabled = $true; $rbBackup.Enabled = $true; $rbManual.Enabled = $true; $cbNic.Enabled = $true; $btnFw.Enabled = $true
            if ($shared.Success) {
                Log-Append '[界面] 刷机完成! 可关闭本工具(自动恢复网卡)'
                [void][System.Windows.Forms.MessageBox]::Show('刷机完成! 浏览器已打开管理页(192.168.1.1)', '完成', 'OK', 'Information')
            }
        }
    }
})
$timer.Start()

Log-Append '[界面] 就绪. 选择模式→网卡→固件, 点开始.'
Log-Append '[界面] 全自动流程: 开始后按住Reset插电即可, 其余全自动.'
[void]$form.ShowDialog()
$timer.Stop()
