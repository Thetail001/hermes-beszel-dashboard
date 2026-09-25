// 安全面板的纯函数工具，独立成模块便于回归测试。
// 之前这些函数散落在 security.tsx（2400+ 行）里，导致"改了一处、另一处遗漏"
//（时区转换漏 bans、IPv6 分隔漏 handleBansQuerySubmit）。抽到这里统一维护。

// datetime-local 的值是无时区的本地时间（YYYY-MM-DDTHH:MM），后端按 UTC 解析。
// 提交前转成 UTC ISO，否则 UTC+8 用户的自定义时间窗口会偏 8 小时。
export function localToUTC(localStr: string): string {
	if (!localStr) return localStr
	const d = new Date(localStr)
	return isNaN(d.getTime()) ? localStr : d.toISOString()
}

// 公共请求函数：检查 response.ok。500/网络错误抛出，而不是把错误 JSON 解析成空数据，
// 否则接口故障会被渲染成"没有攻击者"。
export async function apiJson(url: string): Promise<any> {
	const r = await fetch(url)
	if (!r.ok) throw new Error(`HTTP ${r.status}`)
	return r.json()
}

// 请求序号守卫（R3-04）：单调递增序号 + 过期响应丢弃。切换筛选/机器后，
// 旧查询的慢响应不得覆盖新查询的数据——isCurrent 只认最后一次 next()。
export function createSeqGuard() {
	let current = 0
	return {
		next(): number {
			return ++current
		},
		isCurrent(seq: number): boolean {
			return seq === current
		},
	}
}

/** Rotate 响应验证（R4-02）：HTTP 成功且 deleted 是数字才视为成功，
 * 否则返回 null——不能把 "Deleted undefined events" 这种故障伪装成正常结果。 */
export function parseRotateResult(ok: boolean, body: unknown): number | null {
	if (!ok || !body || typeof body !== "object") return null
	const deleted = (body as { deleted?: unknown }).deleted
	return typeof deleted === "number" ? deleted : null
}

/** IP 时间线的顶层渲染分支（R5-03）。优先级必须固定：
 * loading → 首次失败（列表空+有错误：错误+重试）→ 成功空列表 → 列表。
 * 首次失败绝不能落到 "No events"——那是把故障说成"该 IP 没有记录"。 */
export function timelineView(
	loading: boolean, eventCount: number, loadError: string | null,
): "loading" | "firstError" | "empty" | "list" {
	if (loading && eventCount === 0) return "loading"
	if (eventCount === 0 && loadError) return "firstError"
	if (eventCount === 0) return "empty"
	return "list"
}

/** 导出请求的完整编排（R5-04）：取响应 → 状态检查 → 读正文 → 决定下载，
 * 任一步失败都抛出带原因的错误，绝不返回半成品/错误内容。
 * 返回值含 blob+文件名；调用方只在拿到返回值后才创建下载。 */
export async function fetchExportFile(url: string): Promise<{
	blob: Blob; filename: string; total: string; truncated: boolean
}> {
	const res = await fetch(url)
	if (!res.ok) throw new Error(`HTTP ${res.status}`)
	// 截断确认由调用方处理（需要 UI 交互），这里只负责"成功才有内容"。
	const blob = await res.blob() // 正文中断会在这里抛出——调用方必须接住
	const cd = res.headers.get("Content-Disposition") || ""
	const m = cd.match(/filename="?([^";]+)"?/)
	return {
		blob,
		filename: m ? m[1] : "",
		total: res.headers.get("X-Total-Count") || "",
		truncated: res.headers.get("X-Truncated") === "true",
	}
}

// 公共 key:value 分隔：只切第一个冒号，IPv6 值 ip:2606:4700::abcd 不会被截成 ip=2606。
export function splitKeyValue(part: string): [string, string] | null {
	const idx = part.indexOf(":")
	if (idx <= 0) return null
	return [part.slice(0, idx), part.slice(idx + 1)]
}

/** 计数显示：≥1,000 用 K/M/B 紧凑记法（1.2K / 3.4M / 5.6B），以下原样。
 * 面板跑的是 SUM(count) 量级（分钟窗口聚合的总命中数），上量后裸数字
 * （12,345,678）在卡片/图例里不可读。Intl compact 自动选单位。
 * 抽到这里统一维护——security.tsx 的卡片、环形图、列表计数全部走这一个函数。 */
export function formatCount(n: number | null | undefined): string {
	if (n == null) return "-"
	if (n >= 1_000) {
		return new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 }).format(n)
	}
	return n.toLocaleString("en")
}

// Split-by-machine 图表的配色盘。机器数少（3~5 台），固定盘 + 取模回退；
// 颜色与事件类型盘（TYPE_COLORS）区分，避免同图撞色。
const MACHINE_COLORS = [
	"#3b82f6", // blue
	"#ef4444", // red
	"#22c55e", // green
	"#f59e0b", // amber
	"#a855f7", // purple
	"#06b6d4", // cyan
	"#f97316", // orange
	"#84cc16", // lime
]

/** 机器稳定取色：同一台机器在任何图里颜色一致（按机器序数取盘）。 */
export function machineColor(index: number): string {
	return MACHINE_COLORS[((index % MACHINE_COLORS.length) + MACHINE_COLORS.length) % MACHINE_COLORS.length]
}
