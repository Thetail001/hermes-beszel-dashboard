import { describe, it, expect, vi } from "vitest"
import { buildChartRows, chartTickLabel, localToUTC, splitKeyValue, apiJson, createSeqGuard, fetchExportFile, machineColorFor, machineRowKey, parseRotateResult, timelineView, formatCount, machineColor } from "./security-utils"

describe("localToUTC", () => {
	it("datetime-local 值转成带时区偏移的 ISO", () => {
		const out = localToUTC("2026-09-07T12:00")
		expect(out).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/)
	})

	it("空字符串原样返回", () => {
		expect(localToUTC("")).toBe("")
	})
})

describe("splitKeyValue", () => {
	it("IPv6 值不被截断（审阅报告的关键漏修点）", () => {
		expect(splitKeyValue("ip:2606:4700::abcd")).toEqual(["ip", "2606:4700::abcd"])
	})

	it("普通 key:value", () => {
		expect(splitKeyValue("jail:sshd")).toEqual(["jail", "sshd"])
	})

	it("无冒号返回 null", () => {
		expect(splitKeyValue("novalue")).toBeNull()
	})

	it("空 key（:value）返回 null", () => {
		expect(splitKeyValue(":value")).toBeNull()
	})
})

describe("apiJson", () => {
	it("response.ok 时返回 JSON", async () => {
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve({ a: 1 }) }))
		expect(await apiJson("/x")).toEqual({ a: 1 })
		vi.unstubAllGlobals()
	})

	it("response 非 ok 时抛错（500 不再被解析成空数据）", async () => {
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 500 }))
		await expect(apiJson("/x")).rejects.toThrow("HTTP 500")
		vi.unstubAllGlobals()
	})
})

describe("createSeqGuard", () => {
	it("逆序响应：旧请求的晚到响应不得覆盖新数据（R3-04 切机器场景）", () => {
		// 模拟：先选机器 A 再切到 B，B 的响应先回来、A 的慢响应后回来
		const g = createSeqGuard()
		const seqA = g.next() // 选 A
		const seqB = g.next() // 切到 B

		let buckets: string | null = null
		// B 先返回 → 接受
		if (g.isCurrent(seqB)) buckets = "B-data"
		// A 后返回 → 必须被丢弃
		if (g.isCurrent(seqA)) buckets = "A-data"

		expect(buckets).toBe("B-data") // 最终状态属于最后选择的机器
	})

	it("同序响应：只认最后一次 next()", () => {
		const g = createSeqGuard()
		const s1 = g.next()
		expect(g.isCurrent(s1)).toBe(true)
		const s2 = g.next()
		expect(g.isCurrent(s1)).toBe(false)
		expect(g.isCurrent(s2)).toBe(true)
	})
})

describe("parseRotateResult（R4-02：rotate 失败不能伪装成成功）", () => {
	it("HTTP 200 + deleted 数字 → 返回删除数", () => {
		expect(parseRotateResult(true, { deleted: 42 })).toBe(42)
		expect(parseRotateResult(true, { deleted: 0 })).toBe(0) // 0 也是合法结果
	})

	it("HTTP 500 + 错误 JSON → null（不是 undefined 拼接成功文案）", () => {
		expect(parseRotateResult(false, { error: "boom" })).toBe(null)
	})

	it("HTTP 200 但 deleted 缺失/非数字 → null（响应无效）", () => {
		expect(parseRotateResult(true, {})).toBe(null)
		expect(parseRotateResult(true, { deleted: "12" })).toBe(null)
		expect(parseRotateResult(true, null)).toBe(null)
		expect(parseRotateResult(true, undefined)).toBe(null)
	})
})

describe("timelineView（R5-03：首次失败不能落到 No events）", () => {
	it("首次加载失败（空列表+错误）→ firstError 而非 empty", () => {
		expect(timelineView(false, 0, "Failed to load events: HTTP 500")).toBe("firstError")
	})

	it("成功返回空列表（无错误）→ empty", () => {
		expect(timelineView(false, 0, null)).toBe("empty")
	})

	it("加载中且还没有数据 → loading（错误也不能抢）", () => {
		expect(timelineView(true, 0, "stale")).toBe("loading")
	})

	it("有数据 → list（翻页失败的错误 UI 由列表分支内部处理）", () => {
		expect(timelineView(false, 5, "page 2 failed")).toBe("list")
		expect(timelineView(true, 5, null)).toBe("list") // 翻页 loading 不遮已有列表
	})
})

describe("fetchExportFile（R5-04：完整操作异常边界）", () => {
	it("响应头成功后正文读取中断 → 抛出且不返回 blob", async () => {
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
			ok: true,
			headers: new Headers({ "Content-Disposition": 'attachment; filename="x.csv"' }),
			blob: () => Promise.reject(new Error("body stream reset")),
		}))
		await expect(fetchExportFile("/export")).rejects.toThrow("body stream reset")
		vi.unstubAllGlobals()
	})

	it("HTTP 失败 → 抛出 HTTP 状态，不读正文", async () => {
		const blob = vi.fn()
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
			ok: false, status: 500, blob,
		}))
		await expect(fetchExportFile("/export")).rejects.toThrow("HTTP 500")
		expect(blob).not.toHaveBeenCalled()
		vi.unstubAllGlobals()
	})

	it("成功 → 返回 blob、文件名、截断信息", async () => {
		const fakeBlob = { size: 10 }
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
			ok: true,
			headers: new Headers({
				"Content-Disposition": 'attachment; filename="security-events.csv"',
				"X-Total-Count": "12345",
				"X-Truncated": "true",
			}),
			blob: () => Promise.resolve(fakeBlob),
		}))
		const r = await fetchExportFile("/export")
		expect(r.blob).toBe(fakeBlob)
		expect(r.filename).toBe("security-events.csv")
		expect(r.total).toBe("12345")
		expect(r.truncated).toBe(true)
		vi.unstubAllGlobals()
	})
})

describe("formatCount（K/M/B 紧凑记法）", () => {
	it("null/undefined 显示 -", () => {
		expect(formatCount(null)).toBe("-")
		expect(formatCount(undefined)).toBe("-")
	})

	it("千以下原样显示", () => {
		expect(formatCount(0)).toBe("0")
		expect(formatCount(999)).toBe("999")
	})

	it("千级用 K", () => {
		expect(formatCount(1500)).toBe("1.5K")
		expect(formatCount(12345)).toBe("12.3K")
	})

	it("百万级用 M、十亿级用 B", () => {
		expect(formatCount(3_400_000)).toBe("3.4M")
		expect(formatCount(5_600_000_000)).toBe("5.6B")
	})
})

describe("machineColor（机器配色盘）", () => {
	it("同一序数颜色稳定", () => {
		expect(machineColor(0)).toBe(machineColor(0))
		expect(machineColor(2)).toMatch(/^#/)
	})

	it("越界取模回绕，不抛错", () => {
		expect(machineColor(8)).toBe(machineColor(0))
		expect(machineColor(17)).toBe(machineColor(1))
	})
})

describe("buildChartRows（审阅 P2-3：机器名不得污染统计键）", () => {
	it("恶意机器名（__total/label/scan/__proto__）写入 __m_ 命名空间，统计键完好", () => {
		// by_machine 走 JSON.parse 构造：真实 API 数据里 __proto__ 是普通 own key，
		// 对象字面量则会把它当成原型设置（JS 坑），两种形态都要过。
		const { chartData, activeMachines } = buildChartRows(
			[
				{
					key: "2026-09-25 13:00",
					total: 6,
					unique_ips: 2,
					by_type: { scan: 6 },
					by_machine: JSON.parse('{"__total":3,"label":1,"__proto__":2}'),
				},
			],
			"hour",
		)
		const row = chartData[0]
		expect(row.__total).toBe(6) // 未被名为 __total 的机器覆盖
		expect(row.label).toBe("13:00") // 轴标签未被名为 label 的机器覆盖
		expect(row.scan).toBe(6) // 类型键未被同名机器覆盖
		expect(row[machineRowKey("__total")]).toBe(3)
		expect(row[machineRowKey("label")]).toBe(1)
		expect(row[machineRowKey("__proto__")]).toBe(2)
		expect(Object.keys(row)).not.toContain("__proto__")
		// 机器按窗口总量降序：__total(3) > __proto__(2) > label(1)
		expect(activeMachines).toEqual(["__total", "__proto__", "label"])
	})

	it("by_machine 缺省时退化为普通图表", () => {
		const { chartData, activeTypes, activeMachines } = buildChartRows(
			[{ key: "2026-09-25", total: 5, unique_ips: 4, by_type: { attack: 5 } }],
			"day",
		)
		expect(chartData[0].label).toBe("25")
		expect(chartData[0].attack).toBe(5)
		expect(activeTypes).toEqual(["attack"])
		expect(activeMachines).toEqual([])
	})
})

describe("chartTickLabel", () => {
	it("hour/day/month 三种粒度", () => {
		expect(chartTickLabel("2026-09-25 13:00", "hour")).toBe("13:00")
		expect(chartTickLabel("2026-09-25", "day")).toBe("25")
		expect(chartTickLabel("2026-09", "month")).toBe(
			new Date(2000, 8, 1).toLocaleDateString(undefined, { month: "short" }),
		)
	})
})

describe("machineColorFor（审阅 P2-4：颜色绑定机器标识，不随排名漂移）", () => {
	it("同一台机器颜色与列表顺序无关", () => {
		const ids = ["HK-01", "DE-01", "US-01"]
		expect(machineColorFor("DE-01", ids)).toBe(machineColorFor("DE-01", [...ids].reverse()))
		expect(machineColorFor("DE-01", ids)).toBe(machineColor(1))
		expect(machineColorFor("US-01", ids)).toBe(machineColor(2))
	})

	it("列表外机器按 id 哈希回退且稳定", () => {
		const ids = ["HK-01"]
		expect(machineColorFor("GHOST", ids)).toBe(machineColorFor("GHOST", ids))
		expect(machineColorFor("GHOST", ids)).toMatch(/^#/)
	})
})
