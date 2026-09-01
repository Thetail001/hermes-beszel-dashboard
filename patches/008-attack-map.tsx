import { Trans } from "@lingui/react/macro"
import { useEffect, useRef, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { geoEqualEarth, geoPath } from "d3-geo"
import { feature } from "topojson-client"

// ---------------------------------------------------------------- types
interface SecurityEvent {
	id: number
	ts: string
	machine_id: string
	event_type: string
	src_ip: string
	jail: string | null
	uri: string | null
	ua: string | null
	username: string | null
	country: string | null
	asn: string | null
	lat: number | null
	lon: number | null
	raw_excerpt: string | null
	count: number
	burst: number
}

interface Ban {
	id: number
	ip: string
	jail: string
	machine_id: string
	banned_at: string
	unbanned_at: string | null
}

interface Summary {
	period: string
	total_events: number
	active_bans: number
	unique_ips: number
	by_type: Record<string, number>
	by_jail: Record<string, number>
}

interface Machine {
	id: string
	name: string
	host: string
	status: string
	country?: string
	city?: string
	lat?: number
	lon?: number
}

interface Attacker {
	src_ip: string
	country: string | null
	lat: number | null
	lon: number | null
	total_events: number
	last_seen: string
	first_seen: string
	types: string
}

interface FilterState {
	period: string
	start: string
	end: string
	type: string
	country: string
	ip: string
	sort: string
	machine_id: string
}

// ---------------------------------------------------------------- helpers
const EVENT_COLORS: Record<string, string> = {
	ban: "bg-red-500/10 text-red-500 border-red-500/20",
	unban: "bg-green-500/10 text-green-500 border-green-500/20",
	attack: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
	scan: "bg-blue-500/10 text-blue-500 border-blue-500/20",
	auth_fail: "bg-orange-500/10 text-orange-500 border-orange-500/20",
	auth_success: "bg-emerald-500/10 text-emerald-500 border-emerald-500/20",
}

const TYPE_COLORS: Record<string, string> = {
	ban: "#ef4444",
	unban: "#22c55e",
	attack: "#eab308",
	scan: "#3b82f6",
	auth_fail: "#f97316",
	auth_success: "#10b981",
}

function timeAgo(iso: string): string {
	const diff = Date.now() - new Date(iso).getTime()
	const m = Math.floor(diff / 60000)
	if (m < 1) return "just now"
	if (m < 60) return `${m}m ago`
	const h = Math.floor(m / 60)
	if (h < 24) return `${h}h ago`
	return `${Math.floor(h / 24)}d ago`
}

function buildQueryString(f: FilterState): string {
	const p = new URLSearchParams()
	if (f.period && f.period !== "custom") p.set("period", f.period)
	if (f.start) p.set("start", f.start)
	if (f.end) p.set("end", f.end)
	if (f.type) p.set("type", f.type)
	if (f.country) p.set("country", f.country)
	if (f.ip) p.set("ip", f.ip)
	if (f.sort) p.set("sort", f.sort)
	if (f.machine_id) p.set("machine_id", f.machine_id)
	return p.toString()
}

function parseQueryInput(input: string): Partial<FilterState> {
	const out: Partial<FilterState> = {}
	const parts = input.trim().split(/\s+/)
	for (const part of parts) {
		const [key, val] = part.split(":", 2)
		if (!val) continue
		if (key === "ip") out.ip = val
		if (key === "type") out.type = val
		if (key === "country") out.country = val
	}
	return out
}

// ---------------------------------------------------------------- sub-components
/** Donut chart: event type distribution */
function TypeDonut({ byType }: { byType: Record<string, number> }) {
	const total = Object.values(byType).reduce((a, b) => a + b, 0)
	if (total === 0) return <div className="text-sm text-muted-foreground">No data</div>

	const size = 80
	const cx = size / 2
	const cy = size / 2
	const r = 30
	const circ = 2 * Math.PI * r

	let offset = 0
	const arcs = Object.entries(byType).map(([type, count]) => {
		const frac = count / total
		const dash = frac * circ
		const arc = (
			<circle
				key={type}
				cx={cx}
				cy={cy}
				r={r}
				fill="none"
				stroke={TYPE_COLORS[type] || "#666"}
				strokeWidth={10}
				strokeDasharray={`${dash} ${circ - dash}`}
				strokeDashoffset={-offset}
				transform={`rotate(-90 ${cx} ${cy})`}
			/>
		)
		offset += dash
		return arc
	})

	return (
		<div className="flex items-center gap-3">
			<svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
				{arcs}
				<text x={cx} y={cy} textAnchor="middle" dominantBaseline="central" className="text-sm font-bold fill-current">
					{total}
				</text>
			</svg>
			<div className="space-y-1">
				{Object.entries(byType).map(([type, count]) => (
					<div key={type} className="flex items-center gap-2 text-xs">
						<div className="h-2 w-2 rounded-full" style={{ backgroundColor: TYPE_COLORS[type] || "#666" }} />
						<span className="capitalize">{type.replace("_", " ")}</span>
						<span className="text-muted-foreground">{count}</span>
					</div>
				))}
			</div>
		</div>
	)
}

/** Sparkline: 24h event density */
function DensitySparkline({ events }: { events: SecurityEvent[] }) {
	if (events.length === 0) return null

	const hours = Array(24).fill(0)
	const now = Date.now()
	for (const ev of events) {
		const h = Math.floor((now - new Date(ev.ts).getTime()) / 3600000)
		if (h >= 0 && h < 24) hours[23 - h]++
	}

	const max = Math.max(...hours, 1)
	const w = 200
	const h = 30
	const bw = w / 24

	return (
		<div className="space-y-1">
			<div className="text-xs text-muted-foreground">24h density</div>
			<svg width={w} height={h} className="block">
				{hours.map((count, i) => (
					<rect
						key={i}
						x={i * bw}
						y={h - (count / max) * h}
						width={bw - 1}
						height={(count / max) * h}
						fill={count > 0 ? "#22c55e" : "#333"}
						rx={1}
					/>
				))}
			</svg>
		</div>
	)
}

/** Attack Map: Canvas-based world map with attack trajectories */
function AttackMap({ events, machines, effectLevel, fusionMode }: {
	events: SecurityEvent[]
	machines: Machine[]
	effectLevel: number
	fusionMode: boolean
}) {
	const canvasRef = useRef<HTMLCanvasElement>(null)
	const containerRef = useRef<HTMLDivElement>(null)
	const [worldData, setWorldData] = useState<any>(null)

	// Load world topology
	useEffect(() => {
		fetch("/dashboard-plugins/beszel/dist/countries-50m.json")
			.then((r) => r.json())
			.then((data) => setWorldData(data))
			.catch(() => setWorldData(null))
	}, [])

	// Canvas render
	useEffect(() => {
		if (!worldData || !canvasRef.current || !containerRef.current) return

		const canvas = canvasRef.current
		const container = containerRef.current
		const ctx = canvas.getContext("2d")
		if (!ctx) return

		// Resize canvas to container
		const rect = container.getBoundingClientRect()
		canvas.width = rect.width * devicePixelRatio
		canvas.height = rect.height * devicePixelRatio
		canvas.style.width = `${rect.width}px`
		canvas.style.height = `${rect.height}px`
		ctx.scale(devicePixelRatio, devicePixelRatio)

		const width = rect.width
		const height = rect.height

		// Projection
		const projection = geoEqualEarth().fitSize([width, height], { type: "Sphere" })
		const path = geoPath(projection, ctx)

		// Clear
		ctx.clearRect(0, 0, width, height)

		// Background
		ctx.fillStyle = "#0a0a0f"
		ctx.fillRect(0, 0, width, height)

		// Graticule (subtle grid)
		if (effectLevel >= 2) {
			ctx.strokeStyle = "rgba(255,255,255,0.03)"
			ctx.lineWidth = 0.5
			const graticule = { type: "LineString", coordinates: [] as any[] }
			for (let lon = -180; lon <= 180; lon += 30) {
				graticule.coordinates = [[lon, -90], [lon, 90]]
				ctx.beginPath()
				path(graticule as any)
				ctx.stroke()
			}
			for (let lat = -60; lat <= 60; lat += 30) {
				graticule.coordinates = [[-180, lat], [180, lat]]
				ctx.beginPath()
				path(graticule as any)
				ctx.stroke()
			}
		}

		// Countries
		const countries = feature(worldData, worldData.objects.countries) as any
		ctx.fillStyle = "rgba(255,255,255,0.04)"
		ctx.strokeStyle = "rgba(255,255,255,0.08)"
		ctx.lineWidth = 0.5
		for (const c of countries.features) {
			ctx.beginPath()
			path(c)
			ctx.fill()
			ctx.stroke()
		}

		// Machine markers
		const machinePositions: Record<string, [number, number]> = {}
		for (const m of machines) {
			if (m.lat && m.lon) {
				const [x, y] = projection([m.lon, m.lat]) || [0, 0]
				machinePositions[m.id] = [x, y]

				// Glow effect
				if (effectLevel >= 3) {
					const gradient = ctx.createRadialGradient(x, y, 0, x, y, 20)
					gradient.addColorStop(0, "rgba(34,197,94,0.3)")
					gradient.addColorStop(1, "transparent")
					ctx.fillStyle = gradient
					ctx.fillRect(x - 20, y - 20, 40, 40)
				}

				// Dot
				ctx.fillStyle = "#22c55e"
				ctx.beginPath()
				ctx.arc(x, y, 4, 0, Math.PI * 2)
				ctx.fill()

				// Pulse ring
				if (effectLevel >= 2) {
					ctx.strokeStyle = "rgba(34,197,94,0.4)"
					ctx.lineWidth = 1
					ctx.beginPath()
					ctx.arc(x, y, 8 + Math.sin(Date.now() / 500) * 2, 0, Math.PI * 2)
					ctx.stroke()
				}

				// Label
				ctx.fillStyle = "rgba(255,255,255,0.6)"
				ctx.font = "10px sans-serif"
				ctx.fillText(m.name, x + 8, y + 4)
			}
		}

		// Attack trajectories (recent events with GeoIP)
		// Performance: object pool for line coordinates, batch rendering
		const attackEvents = events
			.filter((ev) => ev.lat && ev.lon && ev.event_type !== "unban" && ev.event_type !== "auth_success")
			.slice(0, effectLevel >= 3 ? 50 : 20)

		// Pre-calculate all line coordinates
		const lines: Array<{
			sx: number; sy: number; tx: number; ty: number
			midX: number; midY: number; color: string; width: number
		}> = []

		for (const ev of attackEvents) {
			const [sx, sy] = projection([ev.lon!, ev.lat!]) || [0, 0]
			const targetId = fusionMode ? Object.keys(machinePositions)[0] : machines[0]?.id
			const [tx, ty] = targetId ? machinePositions[targetId] || [width / 2, height / 2] : [width / 2, height / 2]

			const dist = Math.sqrt((tx - sx) ** 2 + (ty - sy) ** 2)
			const curvature = Math.min(dist * 0.3, 80)
			const midX = (sx + tx) / 2 + (Math.random() - 0.5) * curvature
			const midY = (sy + ty) / 2 - curvature * 0.5

			lines.push({
				sx, sy, tx, ty, midX, midY,
				color: TYPE_COLORS[ev.event_type] || "#666",
				width: effectLevel >= 3 ? 2 : 1,
			})
		}

		// Batch render lines
		for (const line of lines) {
			ctx.strokeStyle = line.color
			ctx.lineWidth = line.width
			ctx.globalAlpha = 0.6
			ctx.beginPath()
			ctx.moveTo(line.sx, line.sy)
			ctx.quadraticCurveTo(line.midX, line.midY, line.tx, line.ty)
			ctx.stroke()
			ctx.globalAlpha = 1

			// Source dot
			ctx.fillStyle = line.color
			ctx.beginPath()
			ctx.arc(line.sx, line.sy, 3, 0, Math.PI * 2)
			ctx.fill()
		}

		// Particle heads (Level 3 only, staggered)
		if (effectLevel >= 3) {
			const now = Date.now()
			for (let i = 0; i < lines.length; i++) {
				const line = lines[i]
				const t = (now / 1000 + i * 0.15) % 1
				const px = (1 - t) * (1 - t) * line.sx + 2 * (1 - t) * t * line.midX + t * t * line.tx
				const py = (1 - t) * (1 - t) * line.sy + 2 * (1 - t) * t * line.midY + t * t * line.ty
				ctx.fillStyle = "#fff"
				ctx.beginPath()
				ctx.arc(px, py, 2, 0, Math.PI * 2)
				ctx.fill()
			}
		}

		// Animation loop for Level 3 (with FPS adaptive degradation)
		let animId: number
		let frameCount = 0
		let lastFpsCheck = Date.now()
		let degraded = false

		if (effectLevel >= 3) {
			const animate = () => {
				animId = requestAnimationFrame(animate)
				frameCount++

				// FPS check every 5 seconds
				const now = Date.now()
				if (now - lastFpsCheck >= 5000) {
					const fps = frameCount / ((now - lastFpsCheck) / 1000)
					if (fps < 45 && !degraded) {
						degraded = true
						console.warn("[AttackMap] FPS below 45, degrading effects")
					}
					frameCount = 0
					lastFpsCheck = now
				}
			}
			animId = requestAnimationFrame(animate)
		}

		return () => {
			if (animId) cancelAnimationFrame(animId)
		}
	}, [worldData, events, machines, effectLevel, fusionMode])

	return (
		<div ref={containerRef} className="relative h-[400px] w-full overflow-hidden rounded-md border">
			<canvas ref={canvasRef} className="absolute inset-0" />
		</div>
	)
}

/** Pagination bar for the attackers list. Rendered above and below the list. */
function PaginationBar({
	page,
	pageSize,
	total,
	onPageChange,
	onPageSizeChange,
}: {
	page: number
	pageSize: number
	total: number
	onPageChange: (p: number) => void
	onPageSizeChange: (n: number) => void
}) {
	const totalPages = Math.max(1, Math.ceil(total / pageSize))
	const [jump, setJump] = useState("")

	const doJump = () => {
		const n = parseInt(jump, 10)
		if (!Number.isNaN(n) && n >= 1 && n <= totalPages) {
			onPageChange(n)
			setJump("")
		}
	}

	return (
		<div className="flex flex-wrap items-center gap-3 px-4 py-2.5">
			<span className="text-xs text-muted-foreground">
				{total} attacker{total === 1 ? "" : "s"}
			</span>
			<div className="ml-auto flex flex-wrap items-center gap-2">
				<Button
					variant="outline"
					size="sm"
					className="h-7 px-2 text-xs"
					disabled={page <= 1}
					onClick={() => onPageChange(Math.max(1, page - 1))}
				>
					Prev
				</Button>
				<span className="flex items-center gap-1 text-xs text-muted-foreground">
					<input
						type="number"
						min={1}
						max={totalPages}
						value={jump}
						onChange={(e) => setJump(e.target.value)}
						onKeyDown={(e) => e.key === "Enter" && doJump()}
						placeholder={String(page)}
						className="h-7 w-14 rounded-md border bg-background px-1 text-center text-xs"
					/>
					/ {totalPages}
				</span>
				<Button
					variant="outline"
					size="sm"
					className="h-7 px-2 text-xs"
					disabled={page >= totalPages}
					onClick={() => onPageChange(Math.min(totalPages, page + 1))}
				>
					Next
				</Button>
				<select
					value={pageSize}
					onChange={(e) => {
						onPageSizeChange(Number(e.target.value))
						onPageChange(1)
					}}
					className="h-7 rounded-md border bg-background px-1 text-xs"
				>
					{[10, 30, 50, 100].map((n) => (
						<option key={n} value={n}>
							{n} / page
						</option>
					))}
				</select>
			</div>
		</div>
	)
}

/** Collapsible rotation settings card */
function RotationSettings({ onRotate }: { onRotate: (days: number) => void }) {
	const [open, setOpen] = useState(false)
	const [keepDays, setKeepDays] = useState(() => {
		const saved = localStorage.getItem("beszel-security-rotation")
		return saved ? Number(saved) : 90
	})
	const [rotating, setRotating] = useState(false)
	const [lastResult, setLastResult] = useState<string | null>(null)

	const handleRotate = async () => {
		setRotating(true)
		try {
			const r = await fetch(`/api/plugins/beszel/security/rotate?keep_days=${keepDays}`, { method: "POST" })
			const d = await r.json()
			setLastResult(`Deleted ${d.deleted} events older than ${keepDays} days`)
			localStorage.setItem("beszel-security-rotation", String(keepDays))
			onRotate(keepDays)
		} catch {
			setLastResult("Rotation failed")
		} finally {
			setRotating(false)
		}
	}

	return (
		<Card>
			<CardHeader className="cursor-pointer select-none" onClick={() => setOpen(!open)}>
				<CardTitle className="flex items-center gap-2 text-sm">
					<span className="text-muted-foreground">{open ? "▼" : "▶"}</span>
					<Trans>Log Rotation</Trans>
				</CardTitle>
			</CardHeader>
			{open && (
				<CardContent className="space-y-3">
					<div className="flex items-center gap-2">
						<Label className="text-xs"><Trans>Keep days</Trans></Label>
						<Input
							type="number"
							value={keepDays}
							onChange={(e) => setKeepDays(Number(e.target.value))}
							className="h-7 w-20 text-xs"
							min={1}
							max={365}
						/>
						<Button
							variant="outline"
							size="sm"
							className="h-7 text-xs"
							onClick={handleRotate}
							disabled={rotating}
						>
							{rotating ? "…" : "Rotate now"}
						</Button>
					</div>
					{lastResult && <div className="text-xs text-muted-foreground">{lastResult}</div>}
					<div className="text-xs text-muted-foreground">
						<Trans>Auto-rotation runs daily at 03:00 UTC.</Trans>
					</div>
				</CardContent>
			)}
		</Card>
	)
}

// ---------------------------------------------------------------- component
export default function SecurityPage() {
	// Data
	const [events, setEvents] = useState<SecurityEvent[]>([])
	const [attackers, setAttackers] = useState<Attacker[]>([])
	const [bans, setBans] = useState<Ban[]>([])
	const [summary, setSummary] = useState<Summary | null>(null)
	const [machines, setMachines] = useState<Machine[]>([])
	const [loading, setLoading] = useState(true)

	// Pagination (attackers list only — deliberately NOT part of buildQueryString,
	// so it never leaks into events/export/summary, which must stay unpaginated)
	const [page, setPage] = useState(1)
	const [pageSize, setPageSize] = useState(30)
	const [attackerTotal, setAttackerTotal] = useState(0)

	// View state
	const [effectLevel, setEffectLevel] = useState(2)
	const [fusionMode, setFusionMode] = useState(false)
	const [refreshInterval, setRefreshInterval] = useState(30)

	// Filter state
	const [filter, setFilter] = useState<FilterState>({
		period: "7d",
		start: "",
		end: "",
		type: "",
		country: "",
		ip: "",
		sort: "recent",
		machine_id: "",
	})

	// Query input
	const [queryInput, setQueryInput] = useState("")

	// Selected attacker for Level 2
	const [selectedIp, setSelectedIp] = useState<string | null>(null)

	// Load persisted view state
	useEffect(() => {
		const saved = localStorage.getItem("beszel-security-view")
		if (saved) {
			try {
				const parsed = JSON.parse(saved)
				if (parsed.effectLevel !== undefined) setEffectLevel(parsed.effectLevel)
				if (parsed.fusionMode !== undefined) setFusionMode(parsed.fusionMode)
				if (parsed.refreshInterval !== undefined) setRefreshInterval(parsed.refreshInterval)
				if (parsed.filter) {
					// migrate the old 'first_seen' sort key → 'newest'
					const f = { ...parsed.filter }
					if (f.sort === "first_seen") f.sort = "newest"
					setFilter((cur) => ({ ...cur, ...f }))
				}
			} catch {}
		}
	}, [])

	// Persist view state
	useEffect(() => {
		localStorage.setItem(
			"beszel-security-view",
			JSON.stringify({ effectLevel, fusionMode, refreshInterval, filter })
		)
	}, [effectLevel, fusionMode, refreshInterval, filter])

	// Reset to page 1 whenever any filter changes (a new filter means a new
	// result set — staying on page 5 of the old set would show stale/empty data).
	useEffect(() => {
		setPage(1)
	}, [filter])

	const fetchData = () => {
		setLoading(true)
		const qs = buildQueryString(filter)
		const offset = (page - 1) * pageSize
		Promise.all([
			fetch(`/api/plugins/beszel/security/events?limit=50&${qs}`).then((r) => r.json()),
			fetch(`/api/plugins/beszel/security/attackers?${qs}&limit=${pageSize}&offset=${offset}`).then((r) => r.json()),
			fetch(`/api/plugins/beszel/security/bans/current?${qs}`).then((r) => r.json()),
			fetch(`/api/plugins/beszel/security/stats/summary?${qs}`).then((r) => r.json()),
			fetch("/api/plugins/beszel/security/machines").then((r) => r.json()),
		])
			.then(([ev, at, bn, sm, mc]) => {
				setEvents(ev.items || [])
				setAttackers(at.items || [])
				setAttackerTotal(at.total ?? (at.items || []).length)
				setBans(bn.items || [])
				setSummary(sm)
				setMachines(mc.items || [])
			})
			.finally(() => setLoading(false))
	}

	// Initial load + filter changes
	useEffect(() => {
		fetchData()
	}, [filter, page, pageSize])

	// Auto-refresh polling
	useEffect(() => {
		if (refreshInterval <= 0) return
		const id = setInterval(fetchData, refreshInterval * 1000)
		return () => clearInterval(id)
	}, [refreshInterval])

	const handleQuerySubmit = () => {
		const parsed = parseQueryInput(queryInput)
		setFilter((f) => ({ ...f, ...parsed }))
	}

	const handleExport = (format: "json" | "csv") => {
		const qs = buildQueryString(filter)
		window.open(`/api/plugins/beszel/security/export?${qs}&format=${format}`, "_blank")
	}

	const handleRotate = (_days: number) => {
		// Refresh data after rotation
		fetchData()
	}

	// Filter bans by current filter
	const filteredBans = filter.ip
		? bans.filter((b) => b.ip === filter.ip)
		: bans

	// If an IP is selected, show Level 2
	if (selectedIp) {
		return (
			<IpTimeline
				ip={selectedIp}
				onBack={() => setSelectedIp(null)}
			/>
		)
	}

	return (
		<div className="space-y-4">
			{/* Header */}
			<div className="flex items-center justify-between">
				<h1 className="text-2xl font-semibold tracking-tight">
					<Trans>Security</Trans>
				</h1>
				<div className="flex items-center gap-4">
					<div className="flex items-center gap-2">
						<Label className="text-xs"><Trans>Refresh</Trans></Label>
						<select
							value={refreshInterval}
							onChange={(e) => setRefreshInterval(Number(e.target.value))}
							className="h-7 rounded-md border bg-background px-2 text-xs"
						>
							<option value={0}>Off</option>
							<option value={10}>10s</option>
							<option value={30}>30s</option>
							<option value={60}>1m</option>
							<option value={300}>5m</option>
						</select>
						<Button variant="outline" size="sm" className="h-7 px-2 text-xs" onClick={fetchData} disabled={loading}>
							{loading ? "…" : "↻"}
						</Button>
						<Button variant="outline" size="sm" className="h-7 px-2 text-xs" onClick={() => handleExport("json")}>
							JSON
						</Button>
						<Button variant="outline" size="sm" className="h-7 px-2 text-xs" onClick={() => handleExport("csv")}>
							CSV
						</Button>
					</div>
					<div className="flex items-center gap-2">
						<Label htmlFor="fusion" className="text-xs"><Trans>Fusion</Trans></Label>
						<Switch id="fusion" checked={fusionMode} onCheckedChange={setFusionMode} />
					</div>
					<div className="flex items-center gap-2">
						<Label className="text-xs"><Trans>Effects</Trans></Label>
						<div className="flex gap-1">
							{[0, 1, 2, 3].map((level) => (
								<Button
									key={level}
									variant={effectLevel === level ? "default" : "outline"}
									size="sm"
									className="h-6 w-6 p-0 text-xs"
									onClick={() => setEffectLevel(level)}
								>
									{level}
								</Button>
							))}
						</div>
					</div>
				</div>
			</div>

			{/* Stats cards */}
			<div className="grid gap-4 md:grid-cols-4">
				<Card>
					<CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle className="text-sm font-medium"><Trans>Active Bans</Trans></CardTitle>
					</CardHeader>
					<CardContent>
						<div className="text-2xl font-bold">{summary?.active_bans ?? "-"}</div>
						<p className="text-xs text-muted-foreground"><Trans>Currently banned IPs</Trans></p>
					</CardContent>
				</Card>
				<Card>
					<CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle className="text-sm font-medium"><Trans>Events</Trans></CardTitle>
					</CardHeader>
					<CardContent>
						<div className="text-2xl font-bold">{summary?.total_events ?? "-"}</div>
						<DensitySparkline events={events} />
					</CardContent>
				</Card>
				<Card>
					<CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle className="text-sm font-medium"><Trans>Unique IPs</Trans></CardTitle>
					</CardHeader>
					<CardContent>
						<div className="text-2xl font-bold">{summary?.unique_ips ?? "-"}</div>
						<p className="text-xs text-muted-foreground"><Trans>Distinct source IPs</Trans></p>
					</CardContent>
				</Card>
				<Card>
					<CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle className="text-sm font-medium"><Trans>Event Types</Trans></CardTitle>
					</CardHeader>
					<CardContent>
						<TypeDonut byType={summary?.by_type || {}} />
					</CardContent>
				</Card>
			</div>

			{/* Attack map */}
			<Card>
				<CardHeader>
					<CardTitle><Trans>Attack Map</Trans></CardTitle>
				</CardHeader>
				<CardContent>
					<AttackMap events={events} machines={machines} effectLevel={effectLevel} fusionMode={fusionMode} />
				</CardContent>
			</Card>

			{/* Active bans */}
			<Card>
				<CardHeader>
					<CardTitle><Trans>Active Bans</Trans></CardTitle>
				</CardHeader>
				<CardContent>
					{filteredBans.length === 0 ? (
						<div className="py-8 text-center text-muted-foreground"><Trans>No active bans.</Trans></div>
					) : (
						<div className="space-y-1">
							{filteredBans.map((b) => (
								<div key={b.id} className="flex items-center gap-3 rounded-md border px-3 py-2 text-sm">
									<Badge variant="destructive">{b.jail}</Badge>
									<span className="font-mono">{b.ip}</span>
									<span className="ml-auto text-xs text-muted-foreground">{timeAgo(b.banned_at)}</span>
								</div>
							))}
						</div>
					)}
				</CardContent>
			</Card>

			{/* Attackers (Level 1) with integrated filter bar */}
			<Card>
				<CardHeader className="space-y-3">
					<CardTitle><Trans>Attackers</Trans></CardTitle>
					{/* Filter bar inside Attackers card header */}
					<div className="flex flex-wrap items-center gap-3 border-t pt-3">
						<div className="flex items-center gap-2">
							<Input
								placeholder="ip:1.2.3.4 type:ban country:NL"
								value={queryInput}
								onChange={(e) => setQueryInput(e.target.value)}
								onKeyDown={(e) => e.key === "Enter" && handleQuerySubmit()}
								className="h-8 w-64 text-xs"
							/>
							<Button variant="outline" size="sm" className="h-8 text-xs" onClick={handleQuerySubmit}>
								<Trans>Query</Trans>
							</Button>
						</div>
						<select
							value={filter.period}
							onChange={(e) => setFilter((f) => ({ ...f, period: e.target.value, start: "", end: "" }))}
							className="h-8 rounded-md border bg-background px-2 text-xs"
						>
							<option value="24h">Last 24h</option>
							<option value="7d">Last 7d</option>
							<option value="30d">Last 30d</option>
							<option value="custom">Custom</option>
						</select>
						{filter.period === "custom" && (
							<>
								<Input
									type="datetime-local"
									value={filter.start}
									onChange={(e) => setFilter((f) => ({ ...f, start: e.target.value }))}
									className="h-8 text-xs"
								/>
								<span className="text-xs text-muted-foreground">to</span>
								<Input
									type="datetime-local"
									value={filter.end}
									onChange={(e) => setFilter((f) => ({ ...f, end: e.target.value }))}
									className="h-8 text-xs"
								/>
							</>
						)}
						<select
							value={filter.sort}
							onChange={(e) => setFilter((f) => ({ ...f, sort: e.target.value }))}
							className="h-8 rounded-md border bg-background px-2 text-xs"
						>
							<option value="recent">Last active</option>
							<option value="count">Most events</option>
							<option value="newest">Newest attacker</option>
						</select>
						{machines.length > 1 && (
							<select
								value={filter.machine_id}
								onChange={(e) => setFilter((f) => ({ ...f, machine_id: e.target.value }))}
								className="h-8 rounded-md border bg-background px-2 text-xs"
							>
								<option value="">All machines</option>
								{machines.map((m) => (
									<option key={m.id} value={m.name || m.id}>
										{m.name || m.id}
									</option>
								))}
							</select>
						)}
						{(filter.type || filter.country || filter.ip) && (
							<div className="flex items-center gap-1">
								{filter.type && (
									<Badge variant="secondary" className="text-xs">
										type:{filter.type}
										<button className="ml-1" onClick={() => setFilter((f) => ({ ...f, type: "" }))}>×</button>
									</Badge>
								)}
								{filter.country && (
									<Badge variant="secondary" className="text-xs">
										country:{filter.country}
										<button className="ml-1" onClick={() => setFilter((f) => ({ ...f, country: "" }))}>×</button>
									</Badge>
								)}
								{filter.ip && (
									<Badge variant="secondary" className="text-xs">
										ip:{filter.ip}
										<button className="ml-1" onClick={() => setFilter((f) => ({ ...f, ip: "" }))}>×</button>
									</Badge>
								)}
							</div>
						)}
					</div>
					{/* Pagination (top) */}
					{!loading && attackers.length > 0 && (
						<div className="border-t">
							<PaginationBar
								page={page}
								pageSize={pageSize}
								total={attackerTotal}
								onPageChange={setPage}
								onPageSizeChange={setPageSize}
							/>
						</div>
					)}
				</CardHeader>
				<CardContent>
					{loading ? (
						<div className="py-8 text-center text-muted-foreground"><Trans>Loading...</Trans></div>
					) : attackers.length === 0 ? (
						<div className="py-8 text-center text-muted-foreground"><Trans>No attackers in this period.</Trans></div>
					) : (
						<div className="space-y-2">
							{attackers.map((a) => (
								<div
									key={a.src_ip}
									className="cursor-pointer rounded-md border p-3 transition-colors hover:bg-muted/50"
									onClick={() => setSelectedIp(a.src_ip)}
								>
									<div className="flex items-center gap-3">
										<span className="font-mono text-sm font-semibold">{a.src_ip}</span>
										{a.country && <Badge variant="outline" className="text-xs">{a.country}</Badge>}
										<span className="text-xs text-muted-foreground">{a.total_events} events</span>
										<span className="ml-auto text-xs text-muted-foreground">{timeAgo(a.last_seen)}</span>
									</div>
									<div className="mt-2 flex flex-wrap gap-1">
										{a.types.split(",").map((t) => (
											<Badge key={t} className={`text-xs ${EVENT_COLORS[t] || ""}`}>
												{t.replace("_", " ")}
											</Badge>
										))}
									</div>
								</div>
							))}
						</div>
					)}
				</CardContent>
				{/* Pagination (bottom) */}
				{!loading && attackers.length > 0 && (
					<div className="border-t">
						<PaginationBar
							page={page}
							pageSize={pageSize}
							total={attackerTotal}
							onPageChange={setPage}
							onPageSizeChange={setPageSize}
						/>
					</div>
				)}
			</Card>

			{/* Rotation settings */}
			<RotationSettings onRotate={handleRotate} />
		</div>
	)
}

// ---------------------------------------------------------------- Level 2: IP Timeline
function IpTimeline({ ip, onBack }: { ip: string; onBack: () => void }) {
	const [events, setEvents] = useState<SecurityEvent[]>([])
	const [geo, setGeo] = useState<any>(null)
	const [loading, setLoading] = useState(true)
	const [hasMore, setHasMore] = useState(false)
	const [cursor, setCursor] = useState<string | null>(null)
	// Expanded event IDs (individual control)
	const [expandedIds, setExpandedIds] = useState<Set<number>>(new Set())

	const fetchTimeline = (before?: string) => {
		setLoading(true)
		const url = before
			? `/api/plugins/beszel/security/events?ip=${ip}&limit=50&before=${before}`
			: `/api/plugins/beszel/security/events?ip=${ip}&limit=50`
		fetch(url)
			.then((r) => r.json())
			.then((d) => {
				if (before) {
					setEvents((prev) => [...prev, ...(d.items || [])])
				} else {
					setEvents(d.items || [])
				}
				setHasMore(d.has_more || false)
				if (d.items?.length > 0) {
					setCursor(d.items[d.items.length - 1].ts)
				}
			})
			.finally(() => setLoading(false))
	}

	useEffect(() => {
		fetchTimeline()
		fetch(`/api/plugins/beszel/security/ip/${ip}`)
			.then((r) => r.json())
			.then((d) => setGeo(d.geo))
			.catch(() => {})
	}, [ip])

	// Group consecutive same-type events (but keep individual IDs for expansion)
	const grouped: Array<SecurityEvent & { count: number; ids: number[] }> = []
	for (const ev of events) {
		const last = grouped[grouped.length - 1]
		if (last && last.event_type === ev.event_type && last.jail === ev.jail) {
			last.count += ev.count || 1
			last.ids.push(ev.id)
		} else {
			grouped.push({ ...ev, count: ev.count || 1, ids: [ev.id] })
		}
	}

	const toggleExpand = (id: number) => {
		setExpandedIds((prev) => {
			const next = new Set(prev)
			if (next.has(id)) next.delete(id)
			else next.add(id)
			return next
		})
	}

	const expandAll = () => {
		const allIds = new Set<number>()
		for (const g of grouped) for (const id of g.ids) allIds.add(id)
		setExpandedIds(allIds)
	}

	const collapseAll = () => setExpandedIds(new Set())

	return (
		<div className="space-y-4">
			<div className="flex items-center gap-4">
				<Button variant="outline" size="sm" onClick={onBack}>
					← <Trans>Back</Trans>
				</Button>
				<h1 className="text-2xl font-semibold tracking-tight font-mono">{ip}</h1>
				{geo && (
					<div className="text-sm text-muted-foreground">
						{geo.country} {geo.asn} {geo.lat && geo.lon ? `(${geo.lat.toFixed(2)}, ${geo.lon.toFixed(2)})` : ""}
					</div>
				)}
				<div className="ml-auto flex gap-2">
					<Button variant="outline" size="sm" className="h-7 text-xs" onClick={expandAll}>
						<Trans>Expand all</Trans>
					</Button>
					<Button variant="outline" size="sm" className="h-7 text-xs" onClick={collapseAll}>
						<Trans>Collapse all</Trans>
					</Button>
				</div>
			</div>

			<Card>
				<CardHeader>
					<CardTitle><Trans>Event Timeline</Trans></CardTitle>
				</CardHeader>
				<CardContent>
					{loading && events.length === 0 ? (
						<div className="py-8 text-center text-muted-foreground"><Trans>Loading...</Trans></div>
					) : events.length === 0 ? (
						<div className="py-8 text-center text-muted-foreground"><Trans>No events for this IP.</Trans></div>
					) : (
						<div className="space-y-1">
							{grouped.map((ev, gi) => (
								<div key={gi} className="rounded-md border">
									{/* Event row */}
									<div
										className="flex cursor-pointer items-center gap-3 px-3 py-2 text-sm hover:bg-muted/50"
										onClick={() => toggleExpand(ev.id)}
									>
										<span className="text-xs text-muted-foreground">{expandedIds.has(ev.id) ? "▼" : "▶"}</span>
										<Badge className={EVENT_COLORS[ev.event_type] || ""}>
											{ev.event_type.replace("_", " ")}
										</Badge>
										{ev.jail && <span className="text-muted-foreground">[{ev.jail}]</span>}
										{ev.username && <span className="font-mono text-xs text-muted-foreground">user={ev.username}</span>}
										{ev.uri && <span className="max-w-[200px] truncate text-muted-foreground">{ev.uri}</span>}
										{ev.count > 1 && <span className="text-muted-foreground">×{ev.count}</span>}
										<span className="ml-auto text-xs text-muted-foreground">{timeAgo(ev.ts)}</span>
									</div>
									{/* Expanded raw log details */}
									{expandedIds.has(ev.id) && (
										<div className="border-t bg-muted/30 px-3 py-2">
											{ev.ids.map((eventId) => {
												const original = events.find((e) => e.id === eventId)
												return original?.raw_excerpt ? (
													<div key={eventId} className="mb-1 last:mb-0">
														<div className="text-xs text-muted-foreground">{original.ts}</div>
														<pre className="mt-1 whitespace-pre-wrap break-all font-mono text-xs">
															{original.raw_excerpt}
														</pre>
													</div>
												) : null
											})}
										</div>
									)}
								</div>
							))}
							{hasMore && (
								<Button
									variant="outline"
									className="w-full mt-2"
									onClick={() => fetchTimeline(cursor!)}
									disabled={loading}
								>
									{loading ? "…" : "Load more"}
								</Button>
							)}
						</div>
					)}
				</CardContent>
			</Card>
		</div>
	)
}
