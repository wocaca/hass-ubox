# hass-ubox — UBox Camera Home Assistant Add-on

UBox camera 实时 H.265 流，纯本地、按需取流：只在有人看时起 qemu 取流管线，无人看
`idle_timeout` 秒后自动停，只留最后一帧当快照。

## 安装

1. HASS → 设置 → Add-ons → ⋮ → Repositories，加：
   `https://github.com/wocaca/hass-ubox`
2. 装 **UBox Camera**，配置里填 `uid` / `username`(admin) / `password`，
   `host_network` 已默认开启（UDP 打洞需要）。
3. 启动后开 `http://<hass-ip>:8089/` 验证画面。

## HASS 接入（configuration.yaml）

```yaml
camera:
  - platform: mjpeg
    name: UBox院子
    mjpeg_url: http://<hass-ip>:8089/video.mjpg
    still_image_url: http://<hass-ip>:8089/snap.jpg
```

缩略图走 `snap.jpg`（缓存帧，不唤醒取流）；点开卡片才连 `video.mjpg` 起流。

## 传输切换（0.2+：中继/直连）

真lib无transport参数，直连/中继是它按局域网可达性自动选的；本版用网络层强制 +
页面按钮实现三态切换（切换约10秒重启取流）：

- 自动：不封路，lib自选（默认）。
- 中继：封局域网发现（UDP/32762），只能走公网relay（异地/跨网段用它）。
- 直连：封全部P4P relay（UDP/20001），只留局域网（同LAN用它，跨网会黑屏）。

页面上有 自动/中继/直连 三个按钮（`POST /api/transport?mode=`），当前模式与是否
真正生效打在 `/stats`（`transport/transport_applied/transport_detail`）。生效需要
容器 `NET_ADMIN` 特权（config已声明）；若环境不给特权，模式只记录不强制，
页面黄字提示。

## 状态

`/stats`：`running/decoded/nals/subs/spawns`，`subs=0` 超过 `idle_timeout`
即停管线；另有 `transport/transport_applied/transport_detail`。

## 结构

```
ubox/
  config.yaml  Add-on 声明（arch: amd64/aarch64，host_network）
  build.yaml   构建基镜像
  Dockerfile   python:3.12-slim + ffmpeg + qemu-aarch64-static(按arch二选一)
  run.py       监管进程：按需起停 qemu→ffmpeg→MJPEG
  bin/         rehost + lib29.so(崩溃补丁版) + qemu双架构二进制
  rootfs/      瘦 bionic（linker64 + libc/dl/m/log/stdc++/c++_shared，~3.4MB）
```

## 限制

- 冷起首帧约 10~20s（会话握手 + 等 IDR 参数集）。
- 停止是 SIGTERM，不管 camera 侧会话槽（靠端侧超时释放）；频繁开/关间隔建议 ≥60s。
- 账号密码只进 Add-on Options，不进镜像不进仓库。
