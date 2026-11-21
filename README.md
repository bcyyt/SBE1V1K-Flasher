# SBE1V1K 免拆刷机助手

Spectrum **SBE1V1K** (Askey RTQ7300T, 高通 IPQ9574) 的免费开源免拆刷机工具——
不拆机、不接 TTL、不敲命令、免密自动登录，**自动备份原厂引导区与射频校准数据**，自动刷写 OpenWrt 固件。

## 功能特性

- **全自动流程**：按住 Reset 插电即可 —— DHCP `option 43 "askey"` 魔法握手 → TFTP 推送启动器+内存系统 → 自动备份 → 自动刷写 → 自动验收
- **自动备份救砖包**：原厂引导链(前32MB) / `0:ART` 射频校准 / 全部小分区 / U-Boot 环境变量，自动回传电脑 `backup\` 目录
- **哈希闸门**：固件 SHA256 电脑/路由器双侧核对，不一致自动熔断不刷
- **图形界面**(WinForms) + 命令行双版本，纯 PowerShell 实现，**零依赖、代码全可审查**
- **恢复原厂**：备份包整体写回（块3），彻底防锁定
- 自动改网卡/防火墙并在退出时完整恢复

## 使用方法

1. 下载 [Releases](../../releases) 里的 `SBE1V1K免拆刷机工具.zip` 解压（或克隆本仓库后按下方补齐 initramfs）
2. 下载 IPQ95XX 系列固件的 `sysupgrade.bin` 放入 `firmware\`
3. 网线连接路由器 **LAN1 口（2.5G）** —— 10G 口在恢复模式不工作！
4. 双击 `启动刷机助手.cmd` → 选全自动 → **按住 Reset 插电保持约12秒松手**
5. 10~15 分钟后浏览器自动打开 <http://192.168.1.1>

详细说明见仓库内 `使用说明.txt`。

## 仓库结构

```
启动刷机助手.cmd                 ← 双击入口
SBE1V1K-Flasher-GUI.ps1          ← 图形界面版主程序
SBE1V1K免拆刷机助手.ps1           ← 命令行备用版
tftp-root/
  rtq7300t_boot_auto_upgrade_fw.img   ← U-Boot 启动器(FIT)
  initramfs.itb                        ← OpenWrt 官方内存系统(<31MB)
firmware/  backup/               ← 放固件 / 救砖包落盘
使用说明.txt / 第二阶段命令.txt
```

## 免责声明

仅适用于 Spectrum SBE1V1K (RTQ7300T)。刷机有风险：**首次请先选「只备份」模式**，
把救砖包另存到 U 盘/网盘后再刷写。`0:ART` 射频校准数据每台设备唯一，丢失无法再生。

## 致谢

- 免拆通道：OpenWrt 论坛 yangzhg（DHCP option 43 "askey" 方法）
- 中文教程：smzdm《SBE1V1K刷机指南，无需拆机串口》
- 内存系统：OpenWrt 官方 snapshot（qualcommbe/ipq95xx）
