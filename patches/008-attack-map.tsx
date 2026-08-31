import { Trans } from "@lingui/react/macro"
import { useEffect, useRef, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
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
	country: string | null
	asn: string | null
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
		const attackEvents = events
			.filter((ev) => ev.country && ev.event_type !== "unban" && ev.event_type !== "auth_success")
			.slice(0, effectLevel >= 3 ? 50 : 20)

		for (const ev of attackEvents) {
			// Source: use country centroid (simplified)
			// In real impl we'd have lat/lon per IP from GeoIP
			const srcLat = 0, srcLon = 0 // placeholder
			const [sx, sy] = projection([srcLon, srcLat]) || [0, 0]

			// Target: first machine or center
			const targetId = fusionMode ? Object.keys(machinePositions)[0] : machines[0]?.id
			const [tx, ty] = targetId ? machinePositions[targetId] || [width / 2, height / 2] : [width / 2, height / 2]

			// Bezier curve
			const midX = (sx + tx) / 2 + (Math.random() - 0.5) * 100
			const midY = (sy + ty) / 2 - 50

			ctx.strokeStyle = TYPE_COLORS[ev.event_type] || "#666"
			ctx.lineWidth = effectLevel >= 3 ? 2 : 1
			ctx.globalAlpha = 0.6
			ctx.beginPath()
			ctx.moveTo(sx, sy)
			ctx.quadraticCurveTo(midX, midY, tx, ty)
			ctx.stroke()
			ctx.globalAlpha = 1

			// Particle head
			if (effectLevel >= 3) {
				const t = (Date.now() / 1000) % 1
				const px = (1 - t) * (1 - t) * sx + 2 * (1 - t) * t * midX + t * t * tx
				const py = (1 - t) * (1 - t) * sy + 2 * (1 - t) * t * midY + t * t * ty
				ctx.fillStyle = "#fff"
				ctx.beginPath()
				ctx.arc(px, py, 2, 0, Math.PI * 2)
				ctx.fill()
			}
		}

		// Animation loop for Level 3
		let animId: number
		if (effectLevel >= 3) {
			const animate = () => {
				animId = requestAnimationFrame(animate)
				// Redraw dynamic elements only
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

// ---------------------------------------------------------------- component
export default function SecurityPage() {
	const [events, setEvents] = useState<SecurityEvent[]>([])
	const [bans, setBans] = useState<Ban[]>([])
	const [summary, setSummary] = useState<Summary | null>(null)
	const [machines, setMachines] = useState<Machine[]>([])
	const [loading, setLoading] = useState(true)
	const [effectLevel, setEffectLevel] = useState(2)
	const [fusionMode, setFusionMode] = useState(false)

	// Load persisted view state
	useEffect(() => {
		const saved = localStorage.getItem("beszel-security-view")
		if (saved) {
			try {
				const { effectLevel: el, fusionMode: fm } = JSON.parse(saved)
				if (el !== undefined) setEffectLevel(el)
				if (fm !== undefined) setFusionMode(fm)
			} catch {}
		}
	}, [])

	// Persist view state
	useEffect(() => {
		localStorage.setItem("beszel-security-view", JSON.stringify({ effectLevel, fusionMode }))
	}, [effectLevel, fusionMode])

	useEffect(() => {
		Promise.all([
			fetch("/api/plugins/beszel/security/events?limit=50").then((r) => r.json()),
			fetch("/api/plugins/beszel/security/bans/current").then((r) => r.json()),
			fetch("/api/plugins/beszel/security/stats/summary?period=24h").then((r) => r.json()),
			fetch("/api/plugins/beszel/pb/api/collections/systems/records").then((r) => r.json()),
		])
			.then(([ev, bn, sm, sys]) => {
				setEvents(ev.items || [])
				setBans(bn.items || [])
				setSummary(sm)
				// Map beszel systems to Machine format
				const machineList = (sys.items || []).map((s: any) => ({
					id: s.id,
					name: s.name,
					host: s.host,
					status: s.status,
					// GeoIP from security events or default
					country: "DE",
					city: "a German city",
					lat: 50.1109,
					lon: 8.6821,
				}))
				setMachines(machineList)
			})
			.finally(() => setLoading(false))
	}, [])

	return (
		<div className="space-y-4">
			<div className="flex items-center justify-between">
				<h1 className="text-2xl font-semibold tracking-tight">
					<Trans>Security</Trans>
				</h1>
				<div className="flex items-center gap-4">
					<div className="flex items-center gap-2">
						<Label htmlFor="fusion" className="text-xs">
							<Trans>Fusion</Trans>
						</Label>
						<Switch id="fusion" checked={fusionMode} onCheckedChange={setFusionMode} />
					</div>
					<div className="flex items-center gap-2">
						<Label className="text-xs">
							<Trans>Effects</Trans>
						</Label>
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

			{/* stats cards */}
			<div className="grid gap-4 md:grid-cols-4">
				<Card>
					<CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle className="text-sm font-medium">
							<Trans>Active Bans</Trans>
						</CardTitle>
					</CardHeader>
					<CardContent>
						<div className="text-2xl font-bold">{summary?.active_bans ?? "-"}</div>
						<p className="text-xs text-muted-foreground">
							<Trans>Currently banned IPs</Trans>
						</p>
					</CardContent>
				</Card>
				<Card>
					<CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle className="text-sm font-medium">
							<Trans>24h Events</Trans>
						</CardTitle>
					</CardHeader>
					<CardContent>
						<div className="text-2xl font-bold">{summary?.total_events ?? "-"}</div>
						<DensitySparkline events={events} />
					</CardContent>
				</Card>
				<Card>
					<CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle className="text-sm font-medium">
							<Trans>Unique IPs</Trans>
						</CardTitle>
					</CardHeader>
					<CardContent>
						<div className="text-2xl font-bold">{summary?.unique_ips ?? "-"}</div>
						<p className="text-xs text-muted-foreground">
							<Trans>Distinct source IPs in 24h</Trans>
						</p>
					</CardContent>
				</Card>
				<Card>
					<CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle className="text-sm font-medium">
							<Trans>Event Types</Trans>
						</CardTitle>
					</CardHeader>
					<CardContent>
						<TypeDonut byType={summary?.by_type || {}} />
					</CardContent>
				</Card>
			</div>

			{/* attack map */}
			<Card>
				<CardHeader>
					<CardTitle>
						<Trans>Attack Map</Trans>
					</CardTitle>
				</CardHeader>
				<CardContent>
					<AttackMap events={events} machines={machines} effectLevel={effectLevel} fusionMode={fusionMode} />
				</CardContent>
			</Card>

			{/* current bans */}
			<Card>
				<CardHeader>
					<CardTitle>
						<Trans>Active Bans</Trans>
					</CardTitle>
				</CardHeader>
				<CardContent>
					{bans.length === 0 ? (
						<div className="py-8 text-center text-muted-foreground">
							<Trans>No active bans.</Trans>
						</div>
					) : (
						<div className="space-y-1">
							{bans.map((b) => (
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

			{/* event stream */}
			<Card>
				<CardHeader>
					<CardTitle>
						<Trans>Event Stream</Trans>
					</CardTitle>
				</CardHeader>
				<CardContent>
					{loading ? (
						<div className="py-8 text-center text-muted-foreground">
							<Trans>Loading...</Trans>
						</div>
					) : events.length === 0 ? (
						<div className="py-8 text-center text-muted-foreground">
							<Trans>No security events recorded.</Trans>
						</div>
					) : (
						<div className="space-y-1">
							{events.map((ev) => (
								<div
									key={ev.id}
									className="flex items-center gap-3 rounded-md border px-3 py-2 text-sm"
								>
									<Badge className={EVENT_COLORS[ev.event_type] || ""}>
										{ev.event_type.replace("_", " ")}
									</Badge>
									<span className="font-mono">{ev.src_ip}</span>
									{ev.country && (
										<span className="text-xs text-muted-foreground">{ev.country}</span>
									)}
									{ev.jail && (
										<span className="text-muted-foreground">[{ev.jail}]</span>
									)}
									{ev.uri && (
										<span className="max-w-[200px] truncate text-muted-foreground">{ev.uri}</span>
									)}
									{ev.count > 1 && (
										<span className="text-muted-foreground">×{ev.count}</span>
									)}
									<span className="ml-auto text-xs text-muted-foreground">
										{timeAgo(ev.ts)}
									</span>
								</div>
							))}
						</div>
					)}
				</CardContent>
			</Card>
		</div>
	)
}
