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

/** 机器稳定取色（按标识，不按当页排名）：优先按 allIds（/security/machines
 * 返回顺序，稳定）分配；列表外的机器（已下线但还有历史事件）按 id 哈希回退。
 * 翻页/自动刷新后窗口内排名会变——若按排名取色，同一台机器的颜色会互换，
 * 用户会把攻击量变化归错机器（审阅 P2-4）。 */
export function machineColorFor(id: string, allIds: string[]): string {
	let idx = allIds.indexOf(id)
	if (idx < 0) {
		let h = 0
		for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) | 0
		idx = Math.abs(h)
	}
	return machineColor(idx)
}

// ---- Events 图表的纯函数（从 security.tsx 抽出，使数据转换可单测）----

export type ChartBucket = "hour" | "day" | "month"

export interface TimeseriesBucketInput {
	key: string
	total: number
	unique_ips: number
	by_type?: Record<string, number>
	by_machine?: Record<string, number>
}

export interface ChartRow {
	label: string
	__total: number
	__uniq: number
	[key: string]: number | string
}

export function chartTickLabel(key: string, bucket: ChartBucket): string {
	if (bucket === "hour") return key.slice(11)
	if (bucket === "day") return String(parseInt(key.slice(8), 10))
	const m = parseInt(key.slice(5), 10)
	return new Date(2000, m - 1, 1).toLocaleDateString(undefined, { month: "short" })
}

/** 机器系列在 chart row 里的内部键前缀。机器名是用户可改的 beszel 系统名，
 * 可能是 "scan"、"__total" 甚至 "__proto__"——必须命名空间隔离，否则机器名
 * 会覆盖总量/轴标签/类型键，即使没勾选机器拆分也会污染普通图表（审阅 P2-3）。 */
export const MACHINE_KEY_PREFIX = "__m_"

export function machineRowKey(machineId: string): string {
	return MACHINE_KEY_PREFIX + machineId
}

/** 后端 timeseries 桶 → recharts 行数据。机器系列写入 __m_ 命名空间，
 * activeMachines 保留原始机器名（图例/取色用），按窗口内总量降序。 */
export function buildChartRows(
	buckets: TimeseriesBucketInput[],
	bucket: ChartBucket,
): { chartData: ChartRow[]; activeTypes: string[]; activeMachines: string[] } {
	const active = new Set<string>()
	const machineTotals = new Map<string, number>()
	const chartData: ChartRow[] = buckets.map((b) => {
		const row: ChartRow = {
			label: chartTickLabel(b.key, bucket),
			__total: b.total,
			__uniq: b.unique_ips,
		}
		for (const [t, c] of Object.entries(b.by_type || {})) {
			row[t] = c
			if (c > 0) active.add(t)
		}
		for (const [m, c] of Object.entries(b.by_machine || {})) {
			row[machineRowKey(m)] = c
			if (c > 0) machineTotals.set(m, (machineTotals.get(m) || 0) + c)
		}
		return row
	})
	const activeMachines = Array.from(machineTotals.entries())
		.sort((a, b) => b[1] - a[1])
		.map((e) => e[0])
	return { chartData, activeTypes: Array.from(active), activeMachines }
}
