import { describe, it, expect, vi } from "vitest"
import { localToUTC, splitKeyValue, apiJson, createSeqGuard, fetchExportFile, parseRotateResult, timelineView } from "./security-utils"

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
