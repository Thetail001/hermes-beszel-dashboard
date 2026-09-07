import { describe, it, expect, vi } from "vitest"
import { localToUTC, splitKeyValue, apiJson, createSeqGuard } from "./security-utils"

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
