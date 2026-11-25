# su 探针最坏路径审计

每次改动探针前先过一遍这张表。任何一条没有封堵措施，就不许上机。

## 已发生过的真实事故

| 事故 | 现象 | 根因 | 状态 |
|---|---|---|---|
| 探针写用户内存 | `linker: error reading /system/etc/ld.config.txt: Bad address`，`which` 链接 liblog.so 失败，`adb fork failed: Bad address` | 在每次 `fstatat`/`faccessat` 上 `copy_to_user_stack` 并改参数指针，写坏了长期驻留进程的用户栈 | **已删除该路径**，改为 getname_flags 只读判断 |
| 双重 hook | 全系统 EFAULT/EINVAL 风暴（11.573s 起） | `hook_compat_syscalln` 在 ARM32 上 `compat_sys_call_table==NULL`，退化成 inline hook，与 `hook_syscalln` 表项 hook 撞在同一函数上 | **ARM 上不再注册 compat 探针**；syscall 探针默认不装 |
| R8 裁 JNI | App 启动即崩 `Bad JNI version returned from JNI_OnLoad` | 删除轮询服务后 `nativeSuPromptPoll` 成为死代码被裁 | **已加 proguard 保留规则**，并在构建后校验 dex |
| 内核标志重启丢失 | 开机后 `su: not found`，不弹窗 | `su_prompt` 是内存态，开机广播没重写 | 开机广播 + App 启动都重新 `controlFeature` |
| 拒绝后拿到普通 shell | 拒绝 su 反而得到 sh | su 可见时 `getname_flags` 会把 su 改写成 sh | 拒绝时 execve 指向 `/system/bin/.su-refused-by-kpatch`（必然 ENOENT） |

## 探针的最坏路径清单

### A. 泄漏 struct filename
- **路径**：探针返回 -ENOENT 但没有 `putname(fn)` → 每次探测泄漏一个 filename
- **最坏后果**：Root 检测服务定时轮询 `which su`，几小时后内核内存耗尽 OOM
- **封堵**：返回错误前必须 `kfunc(putname)(fn)`；若 `putname` 未解析，**跳过探针**而不是泄漏

### B. 误伤正常命令
- **路径**：`comm` 前缀匹配过宽（如把 `sh`、`busybox` 列进去），导致 shell 解析不到 su 或 busybox 全线异常
- **封堵**：名单只含 `which`/`type`/`command`/`whereis`；按 `strlen(name)` 精确前缀比较；`sh`/`mkash`/`busybox` 明确不列入（代码注释写明原因）

### C. 影响 `which sh` 等非 su 路径
- **路径**：匹配逻辑没先比对路径就动返回
- **封堵**：第一道判断就是 `strcmp(name, su_get_path())`，非 su 路径直接 `return`，不碰返回值和内存

### D. 白名单 uid 被误隐藏
- **路径**：`trusted` 判断漏掉 manager 或 root
- **封堵**：`trusted = uid==0 || is_su_allow_uid || is_trusted_manager_uid`，探针分支整段被 `!trusted` 守卫

### E. 功能持久关闭后行为漂移
- **路径**：探针在 `su_prompt` 关闭时仍生效 → 设备表现与官方不一致
- **封堵**：探针整段额外受 `su_prompt_enabled()` 守卫

### F. 拒绝后仍能看到 su
- **路径**：已拒绝 uid 仍走 visible 分支
- **封堵**：`su_prompt_reachable()` 要求 `!is_su_deny_uid`，拒绝即隐身

### G. 探针导致 execve 拿不到 su
- **路径**：shell 执行 su 时被探针拦住
- **封堵**：shell 的 comm 不在名单里；且探针只影响 `getname_flags` 返回，不触碰 execve 钩子

### H. 钩子卸载不匹配
- **路径**：`unhook` 了从未安装的钩子 → 改坏 sys_call_table
- **封堵**：`su_path_probe_hooks_active` 标志守卫；注册/注销必须严格镜像（当前 syscall 探针默认不装，注销逻辑也只处理已装项）

### I. 内核 panic
- **路径**：after-hook 里调 `putname` 时机不对 / 在不可睡眠上下文
- **封堵**：`getname_flags` 的 after-hook 在进程上下文、非原子区；`putname` 只做 `__putname` 级别的释放，KP 已在同函数另一分支使用它（`getname_kernel`+`putname` 组合），风险与现有代码同级

## 上机前必须通过的门槛

1. 编译零新增 warning/error
2. blob 尺寸与 masked md5 记录在案
3. 探针默认关闭，打开后重启自动恢复
4. 上机顺序：先不开探针验证系统正常 → 再开探针 → 立刻验 `ls /system/bin`、`which sh`、`echo ok`、`adb shell` 连开两次
5. 任何 Bad address / Invalid argument / EFAULT → 立刻重启，取 dmesg 定位