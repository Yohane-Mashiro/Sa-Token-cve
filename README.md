## [dromara/Sa-Token](https://github.com/dromara/Sa-Token)反序列化问题

- **影响组件**: sa-token-starter 下的 `sa-token-jboot-plugin` 与 `sa-token-jfinal-plugin`（JDK 原生序列化）；sa-token-jackson（Jackson 多态反序列化）；可选：当 `SaManager` 配置为 `sa-token-fastjson`/`fastjson2` 时，Fastjson 相关路径。
- **漏洞类型**: 不安全的反序列化（可能导致远程代码执行 RCE，具体视运行时类路径与外部可控性而定）
- **CVSS v3.1 估算**: 可能为 9.8 (CRITICAL) 在存在可控输入且可达 gadget 链的条件下；在受限环境或严格白名单下，严重性下降（取决于可利用条件）。

**受影响文件与调用链（精确定位）**

- JDK 原生反序列化（高风险）
  - SaJdkSerializer.java
    - 方法：`deserialize(byte[] bytes)` → `ObjectInputStream.readObject()`
    - 被谁调用：SaTokenCacheDao.java 初始化 `this.serializer = new SaJdkSerializer();`
    - 典型用途：Jboot 缓存/会话对象的序列化与反序列化读取流程。
  - SaJdkSerializer.java
    - 方法：`valueFromBytes(byte[] bytes)` → `ObjectInputStream.readObject()`
    - 被谁调用：SaTokenDaoRedis.java 初始化 `serializer = new SaJdkSerializer();`
    - 典型用途：JFinal Redis DAO 的值/字段序列化读取。
- Jackson 多态反序列化（中-高风险）
  - SaJsonTemplateForJackson.java
    - 构造中启用：`objectMapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL, JsonTypeInfo.As.PROPERTY)`
    - 反序列化方法：`jsonToObject(String jsonStr, Class<T> type)` → `objectMapper.readValue(jsonStr, type)`
    - 绑定位置：SaTokenPluginForJackson.java（通过 `SaManager.setSaJsonTemplate(new SaJsonTemplateForJackson())` 启用）
- Fastjson/Fastjson2（取决于部署/插件选择）
  - SaJsonTemplateForFastjson.java 与 SaJsonTemplateForFastjson2.java
    - 反序列化方法：`JSON.parseObject(jsonStr, type)`
    - 风险等级取决于运行时是否允许 autoType 或是否使用不受信的数据。

**可利用性细化（何时可导致 RCE）**

- 通用前提（JDK 反序列化）
  - 条件 A：攻击者能够使任意或特定的序列化字节流被写入并随后被系统读取（例如：通过 HTTP 请求写入缓存/Redis；或在共享 Redis 的多应用环境中注入数据）。
  - 条件 B：目标运行时类路径包含可利用的 gadget 类（存在可触发任意命令执行的连锁 gadget），或存在自定义可被滥用的类（可在反序列化过程中任意执行危险动作）。
  - 若 A 与 B 同时满足，则理论上可触发远程代码执行（RCE）。  
  - 若只有 A 满足而 B 不满足，可能发生任意对象创建、并非 RCE（仍可造成逻辑错误、信息泄露、拒绝服务）。
- Jackson 多态（activateDefaultTyping）
  - 条件 A：攻击者可以提交带 `@class`（或 Jackson 指定类型标识）的 JSON 到会被 `jsonToObject` 解析的入口（例如：解析外部 HTTP Body、消息队列消息或反序列化外部提供的配置）。
  - 条件 B：类路径包含 Jackson 可利用的 gadget 或被允许的类型包含不安全类型（由于 `PolymorphicTypeValidator` 在此实现中使用 `allowIfSubType(Object.class)`，几乎等同放行）。
  - 若 A 与 B 同时满足，可能导致 RCE 或任意逻辑执行。
- Fastjson / Fastjson2
  - 条件 A：外部 JSON 到达 `JSON.parseObject` 的路径，且库/配置允许 autoType 或解析到危险类型。
  - 条件 B：存在可利用 gadget。
  - 风险取决于 fastjson 版本和 `autoType` 配置，现代 fastjson2 默认更严格但仍需确认。

**证明性说明**

- JDK 反序列化：`ObjectInputStream.readObject()` 在未设置 `ObjectInputFilter` 或未做类型白名单/校验的情况下，是典型的反序列化入口。该项目中两处序列化器直接读取字节并反序列化，且在常见的缓存/Redis DAO 场景中被调用，存在可被外部注入并随后被读取的实际路径（视部署如何将外部数据写入缓存）。
- Jackson：项目主动启用了 `activateDefaultTyping` 并使用宽松的 `PolymorphicTypeValidator`，从配置角度看属于高风险做法（会允许 JSON 中包含类型信息并进行多态反序列化）。项目对 Map 使用了干净的 `mapObjectMapper`，但 `jsonToObject` 仍会使用启用 typing 的 mapper。
- Fastjson：代码调用 `JSON.parseObject`，需确认运行时是否启用或放宽 autoType。

**影响范围**

- 任何使用默认 JDK 序列化器作为缓存/Redis 序列化器的部署，若缓存数据可被非受信源写入，则存在高风险。
- 使用 Jackson 插件并接受外部 JSON 的模块（例如将 `SaManager` 配置为 Jackson 并用于解析外部请求/消息）存在高风险。
- 使用 Fastjson 插件则取决于其版本与实际配置。

**缓解与修复建议（优先级与示例）**

- 优先：
  - 对 `SaJdkSerializer` 增加 `ObjectInputFilter`（JDK 9+）或自定义白名单检查，示例策略：仅允许反序列化 `java.*` 基础类型与 `cn.dev33.satoken.*` 明确 DTO；拒绝 `org.apache.commons.collections`、`org.springframework` 等常见 gadget 包。  
    - （注意：不要在公开仓库中包含可触发 exploit 的示例 filter 模式；仅在代码中实现白名单逻辑与配置项。）
  - 将 `SaJsonTemplateForJackson` 改为双 Mapper 策略：
    - `safeObjectMapper`（默认用于解析外部输入）——不启用 `activateDefaultTyping`。
    - `unsafeObjectMapper`（仅限受信任持久化场景）——启用 typing 但配严格 `PolymorphicTypeValidator`，仅允许显式包白名单（例如 `cn.dev33.satoken.model.`）。
  - 对 Fastjson：确认 `autoType` 关闭或只允许白名单。
- 长期：
  - 默认将序列化/反序列化方案切换为基于 JSON 的安全流程（明确 DTO、字段白名单）或使用需要显式注册类的二进制序列化库（如 Kryo 的注册模式）。
  - 提供运行时配置项供用户设置允许反序列化的包前缀/类白名单，并在默认配置中禁用危险特性。
  - 在 CI 中加入依赖扫描规则，检测可能的 gadget 类或已知危险库版本。

**补丁建议**

- 对 `SaJdkSerializer.deserialize` / `valueFromBytes` 添加可配置的 `ObjectInputFilter` 支持（基于 JVM 版本条件编译/运行时判断），例如：
  - 增加构造参数或系统配置项 `satoken.serializer.allowedPackages`，默认为 `cn.dev33.satoken,java.*,javax.*` 等。
  - 在反序列化前创建并设置 `ObjectInputFilter`，若 JVM 不支持则记录并拒绝/降级策略（例如拒绝非白名单类型或抛异常）。
- 对 `SaJsonTemplateForJackson` 进行两套 `ObjectMapper` 的区分（如上），并将 `SaManager` 的配置文档更新为警告：默认不要把 Jackson 模板用于解析未经认证的外部 JSON。
