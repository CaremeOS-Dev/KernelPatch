# 发布与合并清单（su 弹窗特性）

验证通过后照着这里做，顺序不能变。

## 0. 前置断言

```bash
# 内核侧：只有两个钩子在用
grep -n "hook_wrap3(getname_flags" kernel/patch/common/sucompat.c
grep -n "su_register_path_probe_hooks" kernel/patch/common/sucompat.c   # 应无输出

# 探针判定与模型一致
cd test && gcc -O1 -std=gnu11 -o /tmp/m su_probe_model.c && /tmp/m      # MODEL OK
```

## 1. 真机验证（唯一的人工闸门）

```bash
fastboot boot Z9-su-prompt-pre.img        # 记录实际 md5
adb install -r APatch-11319-su-prompt-pre.apk
```

必须全部成立：

| # | 检查 | 期望 |
|---|---|---|
| 1 | `ls /system/bin`、`which sh`、`echo ok`、`adb shell` 连开两次 | 正常，无 Bad address / Invalid argument |
| 2 | 未授权 uid 执行 `which su` | 查不到 |
| 3 | 未授权 uid 执行 `su` | 卡住 + 弹窗 |
| 4 | 点「允许」 | 同一进程变 root shell |
| 5 | 点「拒绝」 | `su: not found`，**不是**普通 shell |
| 6 | 拒绝后 `which su` | 查不到 |
| 7 | 白名单 uid `which su` / `su` | 找得到 / 直接 root |
| 8 | 超时（不操作 9 秒） | 按设置裁决，且下次仍弹窗 |
| 9 | 重启后再执行 `su` | 仍会弹窗（内核开关恢复） |
| 10 | 全程 | 无 panic、无重启 |

任何一条不成立 → 停止，取 dmesg/logcat，不要往下走。

## 2. 写 Blob-Verified

```bash
gh pr edit 4 --repo CaremeOS-Dev/KernelPatch --body-file <(cat <<'EOF'
...原正文...
Blob-Verified: <masked md5>
EOF
)
```

`<masked md5>` 必须与实际刷入的 boot.img 里的 blob 一致：

```bash
python3 - <<'PY'
import hashlib
d=open("kpimg-arm-full","rb").read(); e=bytearray(d); e[0x18:0x30]=b"\0"*24
print("masked", hashlib.md5(bytes(e)).hexdigest())
PY
```

## 3. 移动 pin

`KernelPatch/.github/workflows/xtc-arm32.yml:99`

```diff
-          if [ "$masked" != "7374df7788167fc583145bf0e6a22980" ]; then
+          if [ "$masked" != "<masked md5>" ]; then
```

提交信息里带上验证日期与设备序列号（72965335）。

## 4. 合并顺序（不可颠倒）

```
1) KernelPatch #4   —— squash merge（分支需先 rebase，保持线性历史）
2) 等 KernelPatch 的 xtc-arm32 CI 变绿（kpimg == 新 pin）
3) APatch #43       —— squash merge
```

原因：#43 会发送 `ALLOW_ONCE`/`DENY_ONCE`，而 main 上的内核把它们当拒绝。先合 #43 会让所有 su 被拒。

两个仓库都要求：签名提交、线性历史、走 PR、squash。

## 5. 合并后回归

```bash
gh pr checks 4  --repo CaremeOS-Dev/KernelPatch
gh pr checks 43 --repo CaremeOS-Dev/APatch
```

再打一个正式 release（tag 用纯数字，CI 的 `tag: ${{ github.ref_name }}` 只在数字 tag 上置 Latest）。

## 6. 已知未验证项（发布说明里要写）

- 弹窗在 320×360@320dpi（200dpi 渲染 → 256×288dp）下的实际排版没有截图；
- 8.1 上没有背景模糊，只有半透明遮罩；
- `which` 若被检测方以 shell 内建 `command -v` 方式调用，探针无法区分（comm 同样是 `sh`），这是虚拟 su 路径的固有限制。
