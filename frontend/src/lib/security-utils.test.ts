import { describe, it, expect, vi } from "vitest"
import { localToUTC, splitKeyValue, apiJson } from "./security-utils"

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
