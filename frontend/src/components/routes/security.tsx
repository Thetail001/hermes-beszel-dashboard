import { Trans } from "@lingui/react/macro"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { ChartContainer, ChartLegend, ChartLegendContent, ChartTooltip, ChartTooltipContent } from "@/components/ui/chart"
import { Bar, BarChart, CartesianGrid, XAxis, YAxis } from "recharts"
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
	city?: string | null
	asn?: string | null
	org?: string | null
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
	ban_count?: number
	country?: string | null
	city?: string | null
	asn?: string | null
	org?: string | null
	lat?: number | null
	lon?: number | null
}

interface Summary {
	period: string
	total_events: number
	active_bans: number
	unique_ips: number
	by_type: Record<string, number>
	by_jail: Record<string, number>
	geoip?: {
		database_type?: string
		build_month?: string
		build_epoch?: number
		last_checked?: string
		last_updated?: string
		status?: string
		error?: string
	}
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
	city?: string | null
	asn?: string | null
	org?: string | null
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
	asn: string
	org: string
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
	if (f.asn) p.set("asn", f.asn)
	if (f.org) p.set("org", f.org)
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
		if (key === "asn") out.asn = val
		if (key === "org") out.org = val
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

// ---------------------------------------------------------------- Events chart
const EVENT_TYPE_KEYS = Object.keys(TYPE_COLORS)

type ChartBucket = "hour" | "day" | "month"
type ChartMetric = "events" | "unique_ips"

interface TimeseriesBucket {
	key: string
	total: number
	unique_ips: number
	by_type: Record<string, number>
}

function chartWindowLabel(bucket: ChartBucket, keys: string[]): string {
	if (!keys.length) return ""
	if (bucket === "hour") {
		return new Date(keys[0].slice(0, 10) + "T00:00:00").toLocaleDateString(undefined, {
			month: "short",
			day: "numeric",
			year: "numeric",
		})
	}
	if (bucket === "day") {
		const [y, m] = keys[0].split("-").map(Number)
		return new Date(y, m - 1, 1).toLocaleDateString(undefined, { month: "long", year: "numeric" })
	}
	return keys[0].slice(0, 4)
}

function chartTickLabel(key: string, bucket: ChartBucket): string {
	if (bucket === "hour") return key.slice(11)
	if (bucket === "day") return String(parseInt(key.slice(8), 10))
	const m = parseInt(key.slice(5), 10)
	return new Date(2000, m - 1, 1).toLocaleDateString(undefined, { month: "short" })
}

/** Events time-bucket bar chart: hourly/daily/monthly, pan, metric toggle and type stacking. */
function EventsChart({ machineId, refreshInterval }: { machineId: string; refreshInterval: number }) {
	const [bucket, setBucket] = useState<ChartBucket>("hour")
	const [offset, setOffset] = useState(0)
	const [metric, setMetric] = useState<ChartMetric>("events")
	const [splitType, setSplitType] = useState(false)
	const [buckets, setBuckets] = useState<TimeseriesBucket[]>([])

	const load = useCallback(() => {
		// Browser-local timezone offset (minutes east of UTC) keeps buckets
		// aligned with the viewer's calendar days regardless of server TZ.
		const tz = -new Date().getTimezoneOffset()
		const p = new URLSearchParams({
			bucket,
			offset: String(offset),
			tz_offset: String(tz),
		})
		if (machineId) p.set("machine_id", machineId)
		fetch(`/api/plugins/beszel/security/stats/timeseries?${p}`)
			.then((r) => r.json())
			.then((d) => setBuckets(d.buckets || []))
			.catch(() => {})
	}, [bucket, offset, machineId])

	useEffect(() => {
		load()
	}, [load])

	// Auto-refresh, following the global refresh interval.
	useEffect(() => {
		if (refreshInterval <= 0) return
		const id = setInterval(load, refreshInterval * 1000)
		return () => clearInterval(id)
	}, [load, refreshInterval])

	const { chartData, activeTypes } = useMemo(() => {
		const active = new Set<string>()
		const data: any[] = buckets.map((b) => {
			const row: Record<string, number | string> = {
				label: chartTickLabel(b.key, bucket),
				__total: b.total,
				__uniq: b.unique_ips,
			}
			for (const [t, c] of Object.entries(b.by_type)) {
				row[t] = c
				if (c > 0) active.add(t)
			}
			return row
		})
		return { chartData: data, activeTypes: Array.from(active) }
	}, [buckets, bucket])

	// Forward navigation is clamped to the current window (no future buckets).
	const canGoForward = offset < 0
	const isStacked = metric === "events" && splitType

	return (
		<Card>
			<CardHeader className="space-y-3">
				<div className="flex flex-wrap items-center justify-between gap-3">
					<CardTitle><Trans>Events</Trans></CardTitle>
					<div className="flex items-center gap-2">
						<Button variant="outline" size="sm" className="h-7 w-7 p-0 text-xs" onClick={() => setOffset((o) => o - 1)}>
							←
						</Button>
						<span className="min-w-28 text-center text-xs text-muted-foreground">
							{chartWindowLabel(bucket, buckets.map((b) => b.key))}
						</span>
						<Button
							variant="outline"
							size="sm"
							className="h-7 w-7 p-0 text-xs"
							disabled={!canGoForward}
							onClick={() => setOffset((o) => o + 1)}
						>
							→
						</Button>
					</div>
				</div>
				<div className="flex flex-wrap items-center gap-3 border-t pt-3">
					<div className="flex gap-1">
						{(["hour", "day", "month"] as const).map((g) => (
							<Button
								key={g}
								variant={bucket === g ? "default" : "outline"}
								size="sm"
								className="h-7 px-2 text-xs capitalize"
								onClick={() => {
									setBucket(g)
									setOffset(0)
								}}
							>
								{g}
							</Button>
						))}
					</div>
					<div className="flex gap-1">
						<Button
							variant={metric === "events" ? "default" : "outline"}
							size="sm"
							className="h-7 px-2 text-xs"
							onClick={() => setMetric("events")}
						>
							Events
						</Button>
						<Button
							variant={metric === "unique_ips" ? "default" : "outline"}
							size="sm"
							className="h-7 px-2 text-xs"
							onClick={() => setMetric("unique_ips")}
						>
							Unique IPs
						</Button>
					</div>
					{metric === "events" && (
						<label className="flex items-center gap-2 text-xs text-muted-foreground">
							<input
								type="checkbox"
								checked={splitType}
								onChange={(e) => setSplitType(e.target.checked)}
								className="h-3.5 w-3.5"
							/>
							Split by type
						</label>
					)}
				</div>
			</CardHeader>
			<CardContent>
				<ChartContainer className="h-64 w-full">
					<BarChart data={chartData} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
						<CartesianGrid vertical={false} strokeDasharray="3 3" />
						<XAxis dataKey="label" tickLine={false} axisLine={false} minTickGap={12} fontSize={11} />
						<YAxis tickLine={false} axisLine={false} fontSize={11} allowDecimals={false} />
						<ChartTooltip content={<ChartTooltipContent />} />
						{isStacked ? (
							EVENT_TYPE_KEYS.filter((t) => activeTypes.includes(t)).map((t) => (
								<Bar
									key={t}
									dataKey={t}
									name={t.replace("_", " ")}
									stackId="a"
									fill={TYPE_COLORS[t]}
									isAnimationActive={false}
								/>
							))
						) : (
							<Bar
								dataKey={metric === "events" ? "__total" : "__uniq"}
								name={metric === "events" ? "Events" : "Unique IPs"}
								fill="#3b82f6"
								radius={[2, 2, 0, 0]}
								isAnimationActive={false}
							/>
						)}
						{isStacked && <ChartLegend content={<ChartLegendContent />} />}
					</BarChart>
				</ChartContainer>
			</CardContent>
		</Card>
	)
}

/** Attack Map: City-Level Hotspot Radar with clean consolidated trajectories, pan & zoom */
function AttackMap({
	events,
	bans,
	machines,
	effectLevel,
	selectedMachineId,
	onSelectMachine,
}: {
	events: SecurityEvent[]
	bans: Ban[]
	machines: Machine[]
	effectLevel: number
	selectedMachineId?: string
	onSelectMachine?: (id: string) => void
}) {
	const canvasRef = useRef<HTMLCanvasElement>(null)
	const containerRef = useRef<HTMLDivElement>(null)
	const [worldData, setWorldData] = useState<any>(null)

	// Map visual mode: "attackers" or "bans"
	const [mapMode, setMapMode] = useState<"attackers" | "bans">("attackers")

	// Viewport Pan & Zoom
	const [zoom, setZoom] = useState(1.0)
	const [pan, setPan] = useState({ x: 0, y: 0 })
	const [isDragging, setIsDragging] = useState(false)
	const dragStartRef = useRef({ x: 0, y: 0, startPanX: 0, startPanY: 0, didMove: false })

	// Tooltip state
	const [hovered, setHovered] = useState<{
		type: "machine" | "hotspot"
		title: string
		subtitle?: string
		badge?: string
		badgeColor?: string
		details: Array<{ label: string; val: string }>
		x: number
		y: number
	} | null>(null)

	// Load world topology once
	useEffect(() => {
		fetch("/dashboard-plugins/beszel/dist/countries-50m.json")
			.then((r) => r.json())
			.then((data) => setWorldData(data))
			.catch(() => setWorldData(null))
	}, [])

	// Reset zoom & pan
	const handleReset = () => {
		setZoom(1.0)
		setPan({ x: 0, y: 0 })
	}

	const handleZoomIn = () => {
		setZoom((z) => Math.min(8.0, Number((z * 1.25).toFixed(2))))
	}

	const handleZoomOut = () => {
		setZoom((z) => Math.max(0.8, Number((z * 0.8).toFixed(2))))
	}

	// Native non-passive wheel listener for smooth cursor-centered zoom
	useEffect(() => {
		const container = containerRef.current
		if (!container) return

		const onWheel = (e: WheelEvent) => {
			e.preventDefault()
			const rect = container.getBoundingClientRect()
			const cx = e.clientX - rect.left
			const cy = e.clientY - rect.top

			setZoom((curZoom) => {
				const factor = e.deltaY < 0 ? 1.15 : 0.87
				const nextZoom = Math.min(8.0, Math.max(0.8, Number((curZoom * factor).toFixed(2))))
				setPan((curPan) => ({
					x: cx - (cx - curPan.x) * (nextZoom / curZoom),
					y: cy - (cy - curPan.y) * (nextZoom / curZoom),
				}))
				return nextZoom
			})
		}

		container.addEventListener("wheel", onWheel, { passive: false })
		return () => container.removeEventListener("wheel", onWheel)
	}, [])

	// Structure for aggregated City Hotspots
	type CityHotspot = {
		key: string
		lat: number
		lon: number
		pos: [number, number]
		country: string | null
		city: string | null
		uniqueIps: Set<string>
		totalHits: number
		targetMachines: Record<string, number>
		typeBreakdown: Record<string, number>
		primaryType: string
		primaryColor: string
	}

	// Canvas render
	useEffect(() => {
		if (!worldData || !canvasRef.current || !containerRef.current) return

		const canvas = canvasRef.current
		const container = containerRef.current
		const ctx = canvas.getContext("2d")
		if (!ctx) return

		// High DPI canvas buffer
		const rect = container.getBoundingClientRect()
		const dpr = window.devicePixelRatio || 1
		canvas.width = rect.width * dpr
		canvas.height = rect.height * dpr
		canvas.style.width = `${rect.width}px`
		canvas.style.height = `${rect.height}px`
		ctx.scale(dpr, dpr)

		const width = rect.width
		const height = rect.height

		// Projection
		const projection = geoEqualEarth().fitSize([width, height], { type: "Sphere" })
		const path = geoPath(projection, ctx)
		const countries = feature(worldData, worldData.objects.countries) as any

		// Machine positions
		const machinePositions: Record<string, [number, number]> = {}
		for (const m of machines) {
			if (m.lat != null && m.lon != null) {
				const pos = projection([m.lon, m.lat])
				if (pos) {
					if (m.id) machinePositions[m.id] = pos
					if (m.name) machinePositions[m.name] = pos
				}
			}
		}

		const defaultTargetPos: [number, number] =
			(selectedMachineId && machinePositions[selectedMachineId]) ||
			(machines[0]?.id && machinePositions[machines[0].id]) ||
			(machines[0]?.name && machinePositions[machines[0].name]) ||
			[width / 2, height / 2]

		// Prepare unified raw items
		const raw: any[] = mapMode === "attackers" ? events : bans
		const validItems = raw.filter(
			(it) => it.lat != null && it.lon != null && it.event_type !== "unban" && it.event_type !== "auth_success"
		)

		// Aggregate into City Hotspots
		const hotspotsMap: Record<string, CityHotspot> = {}
		for (const it of validItems) {
			const itLat = Number(it.lat)
			const itLon = Number(it.lon)
			const k = `${itLat.toFixed(2)},${itLon.toFixed(2)}`
			if (!hotspotsMap[k]) {
				const pos = projection([itLon, itLat])
				if (!pos) continue
				const cityName = it.city || (it as any).asn || null
				hotspotsMap[k] = {
					key: k,
					lat: itLat,
					lon: itLon,
					pos,
					country: it.country || null,
					city: cityName,
					uniqueIps: new Set(),
					totalHits: 0,
					targetMachines: {},
					typeBreakdown: {},
					primaryType: "",
					primaryColor: mapMode === "bans" ? "#ef4444" : "#3b82f6",
				}
			}

			const h = hotspotsMap[k]
			const ip = it.ip || it.src_ip
			if (ip) h.uniqueIps.add(ip)

			const count = Number(it.count || it.ban_count || 1)
			h.totalHits += count

			const mId = it.machine_id || "default"
			h.targetMachines[mId] = (h.targetMachines[mId] || 0) + count

			const evType = it.event_type || it.jail || "attack"
			h.typeBreakdown[evType] = (h.typeBreakdown[evType] || 0) + count
		}

		// Calculate primary attack type and color per hotspot
		const hotspots = Object.values(hotspotsMap)
		for (const h of hotspots) {
			let maxType = ""
			let maxC = 0
			for (const [t, c] of Object.entries(h.typeBreakdown)) {
				if (c > maxC) {
					maxC = c
					maxType = t
				}
			}
			h.primaryType = maxType
			if (mapMode === "attackers") {
				h.primaryColor = TYPE_COLORS[maxType] || "#3b82f6"
			}
		}

		// Build Consolidated Trajectory Flows (from Hotspot -> Target Machine)
		type StreamFlow = {
			hotspot: CityHotspot
			targetId: string
			sx: number
			sy: number
			tx: number
			ty: number
			midX: number
			midY: number
			hits: number
			color: string
			width: number
			seed: number
		}

		const streamFlows: StreamFlow[] = []
		for (const h of hotspots) {
			for (const [mId, subHits] of Object.entries(h.targetMachines)) {
				// If a specific machine is selected, filter out flows to other machines
				if (selectedMachineId && mId !== selectedMachineId && mId !== "default") {
					continue
				}

				const targetPos = (mId && machinePositions[mId]) || defaultTargetPos
				const sx = h.pos[0]
				const sy = h.pos[1]
				const tx = targetPos[0]
				const ty = targetPos[1]

				const dist = Math.hypot(tx - sx, ty - sy)
				const seed = (Math.abs(Math.sin(h.lat * 123.45 + h.lon * 67.89)) * 100) % 1
				const curveFactor = (seed - 0.5) * 0.4
				const curvature = Math.min(dist * 0.22, 60)
				const midX = (sx + tx) / 2 + curveFactor * curvature
				const midY = (sy + ty) / 2 - curvature * 0.65

				streamFlows.push({
					hotspot: h,
					targetId: mId,
					sx,
					sy,
					tx,
					ty,
					midX,
					midY,
					hits: subHits,
					color: h.primaryColor,
					width: Math.max(0.6 / zoom, 0.4) * (1 + Math.min(Math.log2(subHits + 1), 3) * 0.35),
					seed,
				})
			}
		}

		// Density tiering: Level 0 (15 flows), Level 1 (35 flows), Level 2/3 (All flows)
		let maxFlows = streamFlows.length
		if (effectLevel === 0) maxFlows = 15
		else if (effectLevel === 1) maxFlows = 35
		const activeFlows = streamFlows.sort((a, b) => b.hits - a.hits).slice(0, maxFlows)

		const hasGrid = effectLevel >= 1
		const hasPulse = effectLevel >= 2
		const hasParticles = effectLevel >= 3

		const draw = (time: number) => {
			ctx.clearRect(0, 0, width, height)

			// Background
			ctx.fillStyle = "#0a0a0f"
			ctx.fillRect(0, 0, width, height)

			// Camera Transform
			ctx.save()
			ctx.translate(pan.x, pan.y)
			ctx.scale(zoom, zoom)

			// Graticule (lat/lon grid)
			if (hasGrid) {
				ctx.strokeStyle = "rgba(255,255,255,0.025)"
				ctx.lineWidth = 0.5 / zoom
				const graticule = { type: "LineString", coordinates: [] as any[] }
				for (let lon = -180; lon <= 180; lon += 30) {
					graticule.coordinates = [
						[lon, -90],
						[lon, 90],
					]
					ctx.beginPath()
					path(graticule as any)
					ctx.stroke()
				}
				for (let lat = -60; lat <= 60; lat += 30) {
					graticule.coordinates = [
						[-180, lat],
						[180, lat],
					]
					ctx.beginPath()
					path(graticule as any)
					ctx.stroke()
				}
			}

			// Countries
			ctx.fillStyle = "rgba(255,255,255,0.04)"
			ctx.strokeStyle = "rgba(255,255,255,0.08)"
			ctx.lineWidth = 0.5 / zoom
			for (const c of countries.features) {
				ctx.beginPath()
				path(c)
				ctx.fill()
				ctx.stroke()
			}

			// Trajectory Flow Streams
			for (const flow of activeFlows) {
				const alpha = Math.min(0.22 + Math.log2(flow.hits + 1) * 0.08, 0.6)
				ctx.strokeStyle = flow.color
				ctx.lineWidth = flow.width
				ctx.globalAlpha = alpha
				ctx.beginPath()
				ctx.moveTo(flow.sx, flow.sy)
				ctx.quadraticCurveTo(flow.midX, flow.midY, flow.tx, flow.ty)
				ctx.stroke()
				ctx.globalAlpha = 1.0
			}

			// Photon Particle Stream (Level 3 ONLY)
			if (hasParticles && activeFlows.length > 0) {
				for (let i = 0; i < activeFlows.length; i++) {
					const flow = activeFlows[i]
					const t = (time / 1600 + flow.seed) % 1
					const invT = 1 - t
					const px = invT * invT * flow.sx + 2 * invT * t * flow.midX + t * t * flow.tx
					const py = invT * invT * flow.sy + 2 * invT * t * flow.midY + t * t * flow.ty

					// White photon head with flow color halo
					ctx.fillStyle = "#ffffff"
					ctx.beginPath()
					ctx.arc(px, py, Math.max(1.6 / zoom, 0.9), 0, Math.PI * 2)
					ctx.fill()
				}
			}

			// Hotspot Nodes (City Energy Hubs)
			for (const h of hotspots) {
				const baseR = Math.min(2.4 + Math.log2(h.totalHits + 1) * 0.75, 7.0) / zoom

				// Outer energy halo
				if ((hasPulse || h.totalHits >= 5) && hasGrid) {
					const pulseAdd = hasPulse ? Math.sin(time / 350 + h.lat) * 0.5 : 0
					const haloR = baseR * (1.6 + Math.min(h.uniqueIps.size, 8) * 0.08) + pulseAdd / zoom
					ctx.fillStyle = h.primaryColor
					ctx.globalAlpha = 0.22
					ctx.beginPath()
					ctx.arc(h.pos[0], h.pos[1], Math.max(2 / zoom, haloR), 0, Math.PI * 2)
					ctx.fill()
					ctx.globalAlpha = 1.0
				}

				// Core dot
				ctx.fillStyle = h.primaryColor
				ctx.beginPath()
				ctx.arc(h.pos[0], h.pos[1], baseR, 0, Math.PI * 2)
				ctx.fill()

				// Center bright dot for high-volume hotspots
				if (h.totalHits >= 10) {
					ctx.fillStyle = "#ffffff"
					ctx.beginPath()
					ctx.arc(h.pos[0], h.pos[1], Math.max(0.8 / zoom, 0.5), 0, Math.PI * 2)
					ctx.fill()
				}
			}

			// Machine Target Markers (Our Servers)
			for (const m of machines) {
				if (m.lat != null && m.lon != null) {
					const pos = projection([m.lon, m.lat])
					if (!pos) continue
					const [x, y] = pos

					const isSelected = selectedMachineId ? m.name === selectedMachineId || m.id === selectedMachineId : false
					const isAll = !selectedMachineId
					const isDim = !isAll && !isSelected

					const dotR = (isSelected ? 4.5 : 3.5) / zoom

					// Glow Gradient
					if (hasPulse && !isDim) {
						const gradR = 18 / zoom
						const gradient = ctx.createRadialGradient(x, y, 0, x, y, gradR)
						gradient.addColorStop(0, isSelected ? "rgba(6,182,212,0.35)" : "rgba(34,197,94,0.3)")
						gradient.addColorStop(1, "transparent")
						ctx.fillStyle = gradient
						ctx.fillRect(x - gradR, y - gradR, gradR * 2, gradR * 2)
					}

					// Pulse Ring
					if (hasPulse && !isDim) {
						const pulseOffset = (m.id.charCodeAt(0) || 0) * 10
						const pulse = (7 + Math.sin((time + pulseOffset) / 400) * 2.5) / zoom
						ctx.strokeStyle = isSelected ? "rgba(6,182,212,0.6)" : "rgba(34,197,94,0.5)"
						ctx.lineWidth = Math.max(1.0 / zoom, 0.5)
						ctx.beginPath()
						ctx.arc(x, y, Math.max(2 / zoom, pulse), 0, Math.PI * 2)
						ctx.stroke()
					}

					// Node Dot
					ctx.fillStyle = isSelected ? "#06b6d4" : isDim ? "rgba(34,197,94,0.4)" : "#22c55e"
					ctx.beginPath()
					ctx.arc(x, y, dotR, 0, Math.PI * 2)
					ctx.fill()
				}
			}

			// Text Labels with Collision Detection (Occlusion Culling)
			// Guarantees absolute ZERO overlapping text
			const occupiedBoxes: Array<{ x1: number; y1: number; x2: number; y2: number }> = []
			const canPlace = (x: number, y: number, w: number, h: number) => {
				const pad = 3 / zoom
				const x1 = x - pad
				const y1 = y - pad
				const x2 = x + w + pad
				const y2 = y + h + pad
				for (const b of occupiedBoxes) {
					if (!(x2 < b.x1 || x1 > b.x2 || y2 < b.y1 || y1 > b.y2)) {
						return false
					}
				}
				occupiedBoxes.push({ x1, y1, x2, y2 })
				return true
			}

			// 1. Render Machine Labels (Highest Priority)
			for (const m of machines) {
				if (m.lat != null && m.lon != null) {
					const pos = projection([m.lon, m.lat])
					if (!pos) continue
					const isSelected = selectedMachineId ? m.name === selectedMachineId || m.id === selectedMachineId : false
					const isAll = !selectedMachineId
					const isDim = !isAll && !isSelected

					const dotR = (isSelected ? 4.5 : 3.5) / zoom
					const text = zoom >= 1.6 && m.city ? `${m.name || m.id} · ${m.city}` : m.name || m.id
					const fontSize = Math.max(9.5 / zoom, 5.5)
					ctx.font = `${isSelected ? "bold " : "600 "}${fontSize}px sans-serif`

					const textW = ctx.measureText(text).width
					const lx = pos[0] + dotR + 3 / zoom
					const ly = pos[1] + 3 / zoom

					if (canPlace(lx, ly - fontSize, textW, fontSize)) {
						ctx.fillStyle = isSelected
							? "#06b6d4"
							: isDim
							? "rgba(255,255,255,0.3)"
							: "rgba(255,255,255,0.85)"
						ctx.fillText(text, lx, ly)
					}
				}
			}

			// 2. Render Hotspot City/Country Labels (When zoom >= 1.5x, sorted by volume)
			if (zoom >= 1.5) {
				const sortedHotspots = [...hotspots].sort((a, b) => b.totalHits - a.totalHits)
				for (const h of sortedHotspots) {
					const baseR = Math.min(2.4 + Math.log2(h.totalHits + 1) * 0.75, 7.0) / zoom
					const text = h.city
						? zoom >= 2.0
							? `${h.city} (${h.totalHits})`
							: h.city
						: h.country || ""
					if (!text) continue

					const fontSize = Math.max(8.0 / zoom, 4.5)
					ctx.font = `500 ${fontSize}px sans-serif`
					const textW = ctx.measureText(text).width
					const lx = h.pos[0] + baseR + 2.5 / zoom
					const ly = h.pos[1] + 2.5 / zoom

					if (canPlace(lx, ly - fontSize, textW, fontSize)) {
						ctx.fillStyle = "rgba(255, 255, 255, 0.75)"
						ctx.fillText(text, lx, ly)
					}
				}
			}

			ctx.restore()
		}

		// Animation loop if level >= 2, else single frame
		let animId: number
		if (hasPulse || hasParticles) {
			const renderLoop = (time: number) => {
				draw(time)
				animId = requestAnimationFrame(renderLoop)
			}
			animId = requestAnimationFrame(renderLoop)
		} else {
			draw(0)
		}

		return () => {
			if (animId) cancelAnimationFrame(animId)
		}
	}, [worldData, events, bans, machines, effectLevel, selectedMachineId, mapMode, zoom, pan])

	// Mouse down: start dragging
	const handleMouseDown = (e: React.MouseEvent) => {
		if (e.button !== 0) return
		setIsDragging(true)
		dragStartRef.current = {
			x: e.clientX,
			y: e.clientY,
			startPanX: pan.x,
			startPanY: pan.y,
			didMove: false,
		}
	}

	// Mouse move: dragging or hit-test for hover
	const handleMouseMove = (e: React.MouseEvent) => {
		if (isDragging) {
			const dx = e.clientX - dragStartRef.current.x
			const dy = e.clientY - dragStartRef.current.y
			if (Math.abs(dx) > 3 || Math.abs(dy) > 3) {
				dragStartRef.current.didMove = true
			}
			setPan({
				x: dragStartRef.current.startPanX + dx,
				y: dragStartRef.current.startPanY + dy,
			})
			setHovered(null)
			return
		}

		// Hit-test when hovering
		const container = containerRef.current
		if (!container || !worldData) return
		const rect = container.getBoundingClientRect()
		const mouseX = e.clientX - rect.left
		const mouseY = e.clientY - rect.top

		const width = rect.width
		const height = rect.height
		const projection = geoEqualEarth().fitSize([width, height], { type: "Sphere" })

		// Check machine markers
		for (const m of machines) {
			if (m.lat != null && m.lon != null) {
				const pos = projection([m.lon, m.lat])
				if (!pos) continue
				const sx = pos[0] * zoom + pan.x
				const sy = pos[1] * zoom + pan.y
				if (Math.hypot(mouseX - sx, mouseY - sy) <= 14) {
					setHovered({
						type: "machine",
						title: m.name || m.id,
						subtitle: [m.city, m.country].filter(Boolean).join(", "),
						badge: m.status || "up",
						badgeColor: m.status === "up" ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" : "bg-zinc-500/20 text-zinc-400",
						details: [
							{ label: "Host", val: m.host || "127.0.0.1" },
							{ label: "ID", val: m.id },
						],
						x: mouseX,
						y: mouseY,
					})
					return
				}
			}
		}

		// Check Hotspot markers
		const raw: any[] = mapMode === "attackers" ? events : bans
		const validItems = raw.filter(
			(it) => it.lat != null && it.lon != null && it.event_type !== "unban" && it.event_type !== "auth_success"
		)

		// Aggregate into hotspots for hit-testing
		const hotspotsMap: Record<string, {
			lat: number
			lon: number
			pos: [number, number]
			country: string | null
			city: string | null
			uniqueIps: Set<string>
			totalHits: number
			targets: Set<string>
			mainTypes: Record<string, number>
		}> = {}

		for (const it of validItems) {
			const itLat = Number(it.lat)
			const itLon = Number(it.lon)
			const k = `${itLat.toFixed(2)},${itLon.toFixed(2)}`
			if (!hotspotsMap[k]) {
				const pos = projection([itLon, itLat])
				if (!pos) continue
				const cityName = it.city || (it as any).asn || null
				hotspotsMap[k] = {
					lat: itLat,
					lon: itLon,
					pos,
					country: it.country || null,
					city: cityName,
					uniqueIps: new Set(),
					totalHits: 0,
					targets: new Set(),
					mainTypes: {},
				}
			}
			const h = hotspotsMap[k]
			const ip = it.ip || it.src_ip
			if (ip) h.uniqueIps.add(ip)
			const count = Number(it.count || it.ban_count || 1)
			h.totalHits += count
			if (it.machine_id) h.targets.add(it.machine_id)
			const t = it.event_type || it.jail || "attack"
			h.mainTypes[t] = (h.mainTypes[t] || 0) + count
		}

		for (const h of Object.values(hotspotsMap)) {
			const sx = h.pos[0] * zoom + pan.x
			const sy = h.pos[1] * zoom + pan.y
			if (Math.hypot(mouseX - sx, mouseY - sy) <= 12) {
				const isBan = mapMode === "bans"
				const topType = Object.entries(h.mainTypes).sort((a, b) => b[1] - a[1])[0]?.[0] || "threat"
				setHovered({
					type: "hotspot",
					title: h.city ? `${h.city}, ${h.country}` : h.country || "Attack Hotspot",
					subtitle: `${h.uniqueIps.size} unique source IPs in this city`,
					badge: isBan ? `Banned: ${topType}` : topType,
					badgeColor: isBan ? "bg-red-500/20 text-red-400 border-red-500/30" : "bg-amber-500/20 text-amber-400 border-amber-500/30",
					details: [
						{ label: "Total Hits", val: `× ${h.totalHits}` },
						{ label: "Target", val: Array.from(h.targets).join(", ") || "All" },
					],
					x: mouseX,
					y: mouseY,
				})
				return
			}
		}

		setHovered(null)
	}

	const handleMouseUp = () => {
		setIsDragging(false)
	}

	// Click to focus machine
	const handleClick = (e: React.MouseEvent) => {
		if (dragStartRef.current.didMove) return
		const container = containerRef.current
		if (!container || !worldData) return
		const rect = container.getBoundingClientRect()
		const mouseX = e.clientX - rect.left
		const mouseY = e.clientY - rect.top
		const width = rect.width
		const height = rect.height
		const projection = geoEqualEarth().fitSize([width, height], { type: "Sphere" })

		for (const m of machines) {
			if (m.lat != null && m.lon != null) {
				const pos = projection([m.lon, m.lat])
				if (!pos) continue
				const sx = pos[0] * zoom + pan.x
				const sy = pos[1] * zoom + pan.y
				if (Math.hypot(mouseX - sx, mouseY - sy) <= 16) {
					// Center view on this machine with 2.5x zoom
					const targetZoom = 2.5
					setZoom(targetZoom)
					setPan({
						x: width / 2 - pos[0] * targetZoom,
						y: height / 2 - pos[1] * targetZoom,
					})
					if (onSelectMachine) {
						onSelectMachine(m.name || m.id)
					}
					return
				}
			}
		}
	}

	return (
		<div
			ref={containerRef}
			className="relative h-[420px] w-full overflow-hidden rounded-md border select-none cursor-grab active:cursor-grabbing bg-[#0a0a0f]"
			onMouseDown={handleMouseDown}
			onMouseMove={handleMouseMove}
			onMouseUp={handleMouseUp}
			onMouseLeave={() => {
				setIsDragging(false)
				setHovered(null)
			}}
			onClick={handleClick}
		>
			<canvas ref={canvasRef} className="absolute inset-0" />

			{/* Top Left HUD: Data Source Switch */}
			<div className="absolute top-3 left-3 flex items-center gap-1.5 rounded-lg border bg-background/80 backdrop-blur px-1.5 py-1 text-xs shadow-md z-10">
				<button
					type="button"
					onClick={(e) => {
						e.stopPropagation()
						setMapMode("attackers")
					}}
					className={`flex items-center gap-1 rounded px-2 py-0.5 font-medium transition-colors ${
						mapMode === "attackers"
							? "bg-primary text-primary-foreground shadow-sm"
							: "text-muted-foreground hover:text-foreground"
					}`}
				>
					<span>⚔️</span>
					<Trans>Attackers</Trans>
					<span className="ml-1 opacity-70 text-[10px]">({events.length})</span>
				</button>
				<button
					type="button"
					onClick={(e) => {
						e.stopPropagation()
						setMapMode("bans")
					}}
					className={`flex items-center gap-1 rounded px-2 py-0.5 font-medium transition-colors ${
						mapMode === "bans"
							? "bg-destructive text-destructive-foreground shadow-sm"
							: "text-muted-foreground hover:text-foreground"
					}`}
				>
					<span>🛡️</span>
					<Trans>Active Bans</Trans>
					<span className="ml-1 opacity-70 text-[10px]">({bans.length})</span>
				</button>
			</div>

			{/* Top Right HUD: Zoom Controls & Scale Indicator */}
			<div className="absolute top-3 right-3 flex items-center gap-1 rounded-lg border bg-background/80 backdrop-blur px-1.5 py-1 text-xs shadow-md z-10">
				<button
					type="button"
					onClick={(e) => {
						e.stopPropagation()
						handleZoomIn()
					}}
					title="Zoom In (+)"
					className="h-6 w-6 rounded flex items-center justify-center font-bold text-sm text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
				>
					+
				</button>
				<button
					type="button"
					onClick={(e) => {
						e.stopPropagation()
						handleReset()
					}}
					title="Reset View"
					className="h-6 px-1.5 rounded flex items-center justify-center font-mono text-[11px] text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
				>
					{zoom.toFixed(1)}x
				</button>
				<button
					type="button"
					onClick={(e) => {
						e.stopPropagation()
						handleZoomOut()
					}}
					title="Zoom Out (-)"
					className="h-6 w-6 rounded flex items-center justify-center font-bold text-sm text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
				>
					-
				</button>
			</div>

			{/* Floating Tooltip Card */}
			{hovered && (
				<div
					className="absolute pointer-events-none z-20 rounded-lg border bg-card/95 backdrop-blur px-3 py-2 text-xs shadow-xl min-w-[170px]"
					style={{
						left: Math.min(hovered.x + 12, (containerRef.current?.clientWidth || 300) - 190),
						top: Math.min(hovered.y + 12, (containerRef.current?.clientHeight || 300) - 130),
					}}
				>
					<div className="flex items-center justify-between gap-2 border-b pb-1 mb-1.5">
						<span className="font-semibold text-foreground tracking-tight">{hovered.title}</span>
						{hovered.badge && (
							<span className={`text-[10px] px-1.5 py-0.5 rounded border font-mono ${hovered.badgeColor || "bg-muted text-muted-foreground"}`}>
								{hovered.badge}
							</span>
						)}
					</div>
					{hovered.subtitle && (
						<div className="text-[11px] text-muted-foreground mb-1">{hovered.subtitle}</div>
					)}
					<div className="space-y-0.5 text-[11px]">
						{hovered.details.map((d, idx) => (
							<div key={idx} className="flex justify-between text-muted-foreground">
								<span>{d.label}:</span>
								<span className="font-mono text-foreground font-medium">{d.val}</span>
							</div>
						))}
					</div>
				</div>
			)}
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

	// 静默刷新 + 竞态防护：
	// - fetchSeqRef / bansSeqRef：请求序号，丢弃过期响应（用户改筛选时，慢的旧请求不得覆盖新数据）
	// - pendingCountRef：进行中的"非静默"请求数，多个并发时正确管理 loading
	const fetchSeqRef = useRef(0)
	const pendingCountRef = useRef(0)
	const bansSeqRef = useRef(0)

	// Pagination (attackers list only — deliberately NOT part of buildQueryString,
	// so it never leaks into events/export/summary, which must stay unpaginated)
	const [page, setPage] = useState(1)
	const [pageSize, setPageSize] = useState(30)
	const [attackerTotal, setAttackerTotal] = useState(0)

	// Bans list — independent filter/sort/pagination (bans have their own
	// dimensions: jail/ip/banned_at, no period/country/type aggregation)
	const [bansFilter, setBansFilter] = useState({ ip: "", jail: "", sort: "recent", period: "all", start: "", end: "" })
	const [bansQuery, setBansQuery] = useState("")
	const [bansPage, setBansPage] = useState(1)
	const [bansPageSize, setBansPageSize] = useState(30)
	const [bansTotal, setBansTotal] = useState(0)

	// View state
	const [effectLevel, setEffectLevel] = useState(2)
	const [refreshInterval, setRefreshInterval] = useState(30)

	// Filter state
	const [filter, setFilter] = useState<FilterState>({
		period: "7d",
		start: "",
		end: "",
		type: "",
		country: "",
		asn: "",
		org: "",
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
			JSON.stringify({ effectLevel, refreshInterval, filter })
		)
	}, [effectLevel, refreshInterval, filter])

	// Reset to page 1 whenever any filter changes (a new filter means a new
	// result set — staying on page 5 of the old set would show stale/empty data).
	useEffect(() => {
		setPage(1)
	}, [filter])

	const fetchData = (silent = false) => {
		const seq = ++fetchSeqRef.current
		if (!silent) {
			pendingCountRef.current++
			setLoading(true)
		}
		const qs = buildQueryString(filter)
		const offset = (page - 1) * pageSize
		Promise.all([
			fetch(`/api/plugins/beszel/security/events?limit=200&${qs}`).then((r) => r.json()),
			fetch(`/api/plugins/beszel/security/attackers?${qs}&limit=${pageSize}&offset=${offset}`).then((r) => r.json()),
			fetch(`/api/plugins/beszel/security/stats/summary?${qs}`).then((r) => r.json()),
			fetch("/api/plugins/beszel/security/machines").then((r) => r.json()),
		])
			.then(([ev, at, sm, mc]) => {
				// 过期响应（已有更新的请求发出）直接丢弃，避免旧数据覆盖新数据
				if (seq !== fetchSeqRef.current) return
				setEvents(ev.items || [])
				setAttackers(at.items || [])
				setAttackerTotal(at.total ?? (at.items || []).length)
				setSummary(sm)
				setMachines(mc.items || [])
			})
			.catch(() => {
				// 静默失败：保留旧数据。silent 刷新失败不应打扰用户，非 silent 失败也先兜住
				// 不再冒泡成 unhandled rejection。
			})
			.finally(() => {
				if (!silent) {
					pendingCountRef.current--
					if (pendingCountRef.current <= 0) {
						pendingCountRef.current = 0
						setLoading(false)
					}
				}
			})
	}

	// Bans are fetched separately — they have their own filter/sort/pagination
	// dimensions and must not share the attackers' buildQueryString (which would
	// leak period/country/type params the bans endpoint ignores).
	const fetchBans = () => {
		const seq = ++bansSeqRef.current
		const p = new URLSearchParams()
		if (bansFilter.ip) p.set("ip", bansFilter.ip)
		if (bansFilter.jail) p.set("jail", bansFilter.jail)
		p.set("sort", bansFilter.sort)
		p.set("period", bansFilter.period)
		if (bansFilter.start) p.set("start", bansFilter.start)
		if (bansFilter.end) p.set("end", bansFilter.end)
		p.set("limit", String(bansPageSize))
		p.set("offset", String((bansPage - 1) * bansPageSize))
		if (filter.machine_id) p.set("machine_id", filter.machine_id)
		fetch(`/api/plugins/beszel/security/bans/current?${p}`)
			.then((r) => r.json())
			.then((d) => {
				if (seq !== bansSeqRef.current) return
				setBans(d.items || [])
				setBansTotal(d.total ?? (d.items || []).length)
			})
			.catch(() => {})
	}

	// 自动刷新用 ref 调用最新版 fetchData/fetchBans，避免 setInterval 闭包捕获旧 filter（stale closure）。
	const fetchDataRef = useRef(fetchData)
	fetchDataRef.current = fetchData
	const fetchBansRef = useRef(fetchBans)
	fetchBansRef.current = fetchBans

	// Initial load + filter changes
	useEffect(() => {
		fetchData()
	}, [filter, page, pageSize])

	// Bans: refetch on bans-filter/sort/pagination or machine change
	useEffect(() => {
		fetchBans()
	}, [bansFilter, bansPage, bansPageSize, filter.machine_id])

	// Auto-refresh polling
	useEffect(() => {
		if (refreshInterval <= 0) return
		const id = setInterval(() => {
			fetchDataRef.current(true) // silent：静默更新，不触发 loading，不打断浏览
			fetchBansRef.current()
		}, refreshInterval * 1000)
		return () => clearInterval(id)
	}, [refreshInterval])

	const handleQuerySubmit = () => {
		const parsed = parseQueryInput(queryInput)
		setFilter((f) => ({ ...f, ...parsed }))
	}

	const handleBansQuerySubmit = () => {
		const out: { ip: string; jail: string } = { ip: "", jail: "" }
		for (const part of bansQuery.trim().split(/\s+/)) {
			const [key, val] = part.split(":", 2)
			if (!val) continue
			if (key === "ip") out.ip = val
			if (key === "jail") out.jail = val
		}
		setBansFilter((f) => ({ ...f, ...out }))
		setBansPage(1)
	}

	const handleExport = (format: "json" | "csv") => {
		const qs = buildQueryString(filter)
		window.open(`/api/plugins/beszel/security/export?${qs}&format=${format}`, "_blank")
	}

	const handleRotate = (_days: number) => {
		// Refresh data after rotation
		fetchData()
	}

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
					{machines.length > 1 && (
						<div className="flex items-center gap-2">
							<Label className="text-xs"><Trans>Machine</Trans></Label>
							<select
								value={filter.machine_id}
								onChange={(e) => setFilter((f) => ({ ...f, machine_id: e.target.value }))}
								className="h-7 rounded-md border bg-background px-2 text-xs"
							>
								<option value="">All machines</option>
								{machines.map((m) => (
									<option key={m.id} value={m.name || m.id}>{m.name || m.id}</option>
								))}
							</select>
						</div>
					)}
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
						<Button variant="outline" size="sm" className="h-7 px-2 text-xs" onClick={() => fetchData()} disabled={loading}>
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

			{/* Snapshot cards: all-time, follow only the global machine filter */}
			<div className="grid gap-4 md:grid-cols-3">
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
						<CardTitle className="text-sm font-medium"><Trans>All time Unique IPs</Trans></CardTitle>
					</CardHeader>
					<CardContent>
						<div className="text-2xl font-bold">{summary?.unique_ips ?? "-"}</div>
						<p className="text-xs text-muted-foreground"><Trans>Distinct source IPs</Trans></p>
					</CardContent>
				</Card>
				<Card>
					<CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle className="text-sm font-medium"><Trans>All time Event Types</Trans></CardTitle>
					</CardHeader>
					<CardContent>
						<TypeDonut byType={summary?.by_type || {}} />
					</CardContent>
				</Card>
			</div>

			{/* Events time-series chart */}
			<EventsChart machineId={filter.machine_id} refreshInterval={refreshInterval} />

			{/* Attack map */}
			<Card>
				<CardHeader className="flex flex-row items-center justify-between space-y-0 pb-3">
					<CardTitle><Trans>Attack Map</Trans></CardTitle>
					{summary?.geoip && (
						<div className="flex items-center gap-2 text-xs text-muted-foreground bg-muted/40 px-2.5 py-1 rounded-md border">
							<span
								className={`inline-block h-2 w-2 rounded-full ${
									summary.geoip.status === "updating"
										? "bg-amber-400 animate-pulse"
										: summary.geoip.status === "error"
										? "bg-red-500"
										: "bg-emerald-500"
								}`}
							/>
							<span>
								<Trans>GeoIP DB</Trans>: {summary.geoip.database_type || "DB-IP City"} ({summary.geoip.build_month || "Auto"})
							</span>
							{summary.geoip.last_checked && (
								<span className="hidden sm:inline text-muted-foreground/60">
									· <Trans>Checked</Trans> {summary.geoip.last_checked.slice(0, 10)}
								</span>
							)}
						</div>
					)}
				</CardHeader>
				<CardContent>
					<AttackMap
						events={events}
						bans={bans}
						machines={machines}
						effectLevel={effectLevel}
						selectedMachineId={filter.machine_id}
						onSelectMachine={(id) => setFilter((f) => ({ ...f, machine_id: id }))}
					/>
				</CardContent>
			</Card>

			{/* Active bans */}
			<Card>
				<CardHeader className="space-y-3">
					<CardTitle><Trans>Active Bans</Trans></CardTitle>
					<div className="flex flex-wrap items-center gap-3 border-t pt-3">
						<div className="flex items-center gap-2">
							<Input
								placeholder="ip:1.2.3.4 jail:sshd"
								value={bansQuery}
								onChange={(e) => setBansQuery(e.target.value)}
								onKeyDown={(e) => e.key === "Enter" && handleBansQuerySubmit()}
								className="h-8 w-64 text-xs"
							/>
							<Button variant="outline" size="sm" className="h-8 text-xs" onClick={handleBansQuerySubmit}>
								<Trans>Query</Trans>
							</Button>
						</div>
						<select
							value={bansFilter.sort}
							onChange={(e) => {
								setBansFilter((f) => ({ ...f, sort: e.target.value }))
								setBansPage(1)
							}}
							className="h-8 rounded-md border bg-background px-2 text-xs"
						>
							<option value="recent">Recently banned</option>
							<option value="oldest">Oldest ban</option>
							<option value="ip">By IP</option>
							<option value="jail">By jail</option>
						</select>
						<select
							value={bansFilter.period}
							onChange={(e) => {
								setBansFilter((f) => ({ ...f, period: e.target.value, start: "", end: "" }))
								setBansPage(1)
							}}
							className="h-8 rounded-md border bg-background px-2 text-xs"
						>
							<option value="all">All time</option>
							<option value="24h">Last 24h</option>
							<option value="7d">Last 7d</option>
							<option value="30d">Last 30d</option>
							<option value="custom">Custom</option>
						</select>
						{bansFilter.period === "custom" && (
							<>
								<Input
									type="datetime-local"
									value={bansFilter.start}
									onChange={(e) => setBansFilter((f) => ({ ...f, start: e.target.value }))}
									className="h-8 text-xs"
								/>
								<span className="text-xs text-muted-foreground">to</span>
								<Input
									type="datetime-local"
									value={bansFilter.end}
									onChange={(e) => setBansFilter((f) => ({ ...f, end: e.target.value }))}
									className="h-8 text-xs"
								/>
							</>
						)}
						{(bansFilter.ip || bansFilter.jail) && (
							<div className="flex items-center gap-1">
								{bansFilter.ip && (
									<Badge variant="secondary" className="text-xs">
										ip:{bansFilter.ip}
										<button className="ml-1" onClick={() => setBansFilter((f) => ({ ...f, ip: "" }))}>×</button>
									</Badge>
								)}
								{bansFilter.jail && (
									<Badge variant="secondary" className="text-xs">
										jail:{bansFilter.jail}
										<button className="ml-1" onClick={() => setBansFilter((f) => ({ ...f, jail: "" }))}>×</button>
									</Badge>
								)}
							</div>
						)}
					</div>
					{/* Pagination (top) */}
					{bans.length > 0 && (
						<div className="border-t">
							<PaginationBar
								page={bansPage}
								pageSize={bansPageSize}
								total={bansTotal}
								onPageChange={setBansPage}
								onPageSizeChange={setBansPageSize}
							/>
						</div>
					)}
				</CardHeader>
				<CardContent>
					{bans.length === 0 ? (
						<div className="py-8 text-center text-muted-foreground"><Trans>No active bans.</Trans></div>
					) : (
						<div className="space-y-1">
							{bans.map((b) => (
								<div
									key={b.id}
									className="flex cursor-pointer items-center gap-3 rounded-md border px-3 py-2 text-sm transition-colors hover:bg-muted/50"
									onClick={() => setSelectedIp(b.ip)}
								>
									<Badge variant="destructive">{b.jail}</Badge>
									<span className="font-mono text-sm font-semibold">{b.ip}</span>
									{b.country && <Badge variant="outline" className="text-xs">{b.country}</Badge>}
									{(b.city || b.org || b.asn) && (
										<span className="hidden sm:inline text-xs text-muted-foreground truncate max-w-[280px]">
											{[b.city, b.org || b.asn].filter(Boolean).join(" · ")}
										</span>
									)}
									<span className="ml-auto text-xs text-muted-foreground">{timeAgo(b.banned_at)}</span>
								</div>
							))}
						</div>
					)}
				</CardContent>
				{/* Pagination (bottom) */}
				{bans.length > 0 && (
					<div className="border-t">
						<PaginationBar
							page={bansPage}
							pageSize={bansPageSize}
							total={bansTotal}
							onPageChange={setBansPage}
							onPageSizeChange={setBansPageSize}
						/>
					</div>
				)}
			</Card>

			{/* Attackers (Level 1) with integrated filter bar */}
			<Card>
				<CardHeader className="space-y-3">
					<CardTitle><Trans>Attackers</Trans></CardTitle>
					{/* Filter bar inside Attackers card header */}
					<div className="flex flex-wrap items-center gap-3 border-t pt-3">
						<div className="flex items-center gap-2">
							<Input
								placeholder="ip:1.2.3.4 type:ban country:NL asn:14061 org:amazon"
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
						{(filter.type || filter.country || filter.asn || filter.org || filter.ip) && (
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
								{filter.asn && (
									<Badge variant="secondary" className="text-xs">
										asn:{filter.asn}
										<button className="ml-1" onClick={() => setFilter((f) => ({ ...f, asn: "" }))}>×</button>
									</Badge>
								)}
								{filter.org && (
									<Badge variant="secondary" className="text-xs">
										org:{filter.org}
										<button className="ml-1" onClick={() => setFilter((f) => ({ ...f, org: "" }))}>×</button>
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
					{attackers.length > 0 && (
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
					{loading && attackers.length === 0 ? (
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
									<div className="flex flex-wrap items-center gap-2 sm:gap-3">
										<span className="font-mono text-sm font-semibold">{a.src_ip}</span>
										{a.country && <Badge variant="outline" className="text-xs">{a.country}</Badge>}
										{(a.city || a.org || a.asn) && (
											<span className="text-xs text-muted-foreground truncate max-w-[320px]">
												{[a.city, a.org || a.asn].filter(Boolean).join(" · ")}
											</span>
										)}
										<span className="text-xs text-muted-foreground">({a.total_events} events)</span>
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
				{attackers.length > 0 && (
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
					<div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
						{geo.country && <Badge variant="outline">{geo.country}</Badge>}
						{geo.city && <span>{geo.city}</span>}
						{(geo.asn || geo.org) && (
							<Badge variant="secondary" className="font-mono">
								{[geo.asn, geo.org].filter(Boolean).join(" · ")}
							</Badge>
						)}
						{geo.lat && geo.lon ? (
							<span className="text-muted-foreground/60">
								({geo.lat.toFixed(2)}, {geo.lon.toFixed(2)})
							</span>
						) : null}
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
