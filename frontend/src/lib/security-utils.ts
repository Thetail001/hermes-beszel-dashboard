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

// 公共 key:value 分隔：只切第一个冒号，IPv6 值 ip:2606:4700::abcd 不会被截成 ip=2606。
export function splitKeyValue(part: string): [string, string] | null {
	const idx = part.indexOf(":")
	if (idx <= 0) return null
	return [part.slice(0, idx), part.slice(idx + 1)]
}
