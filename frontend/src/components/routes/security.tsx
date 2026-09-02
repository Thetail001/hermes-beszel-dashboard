import { Trans } from "@lingui/react/macro"
import { useEffect, useRef, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
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
	ban_count?: number
	country?: string | null
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

/** Attack Map: Interactive Canvas-based world map with pan, zoom, LOD & particle trajectories */
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
		type: "machine" | "source"
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

		// Prepare unified items based on mapMode
		type MapItem = {
			id: number | string
			ip: string
			country: string | null
			lat: number
			lon: number
			machine_id: string
			type: string
			count: number
			ts: string
			color: string
		}

		let rawItems: MapItem[] = []
		if (mapMode === "attackers") {
			rawItems = events
				.filter((ev) => ev.lat != null && ev.lon != null && ev.event_type !== "unban" && ev.event_type !== "auth_success")
				.map((ev) => ({
					id: ev.id,
					ip: ev.src_ip,
					country: ev.country,
					lat: ev.lat!,
					lon: ev.lon!,
					machine_id: ev.machine_id,
					type: ev.event_type,
					count: ev.count || 1,
					ts: ev.ts,
					color: TYPE_COLORS[ev.event_type] || "#3b82f6",
				}))
		} else {
			rawItems = bans
				.filter((b) => b.lat != null && b.lon != null)
				.map((b) => ({
					id: b.id,
					ip: b.ip,
					country: b.country || null,
					lat: b.lat!,
					lon: b.lon!,
					machine_id: b.machine_id,
					type: b.jail,
					count: b.ban_count || 1,
					ts: b.banned_at,
					color: "#ef4444",
				}))
		}

		// Density tiering: Level 0 (20), Level 1 (50), Level 2/3 (All)
		let maxLines = rawItems.length
		if (effectLevel === 0) maxLines = 20
		else if (effectLevel === 1) maxLines = 50
		const visibleItems = rawItems.slice(0, maxLines)

		// Pre-calculate trajectories
		const lines: Array<{
			item: MapItem
			sx: number
			sy: number
			tx: number
			ty: number
			midX: number
			midY: number
			color: string
			width: number
			seed: number
			radius: number
		}> = []

		for (const item of visibleItems) {
			const sourcePos = projection([item.lon, item.lat])
			if (!sourcePos) continue
			const [sx, sy] = sourcePos

			const targetPos = (item.machine_id && machinePositions[item.machine_id]) || defaultTargetPos
			const [tx, ty] = targetPos

			const dist = Math.hypot(tx - sx, ty - sy)
			const seed = Math.abs(((Number(item.id) || 1) * 37 + (item.ip ? item.ip.charCodeAt(0) * 19 : 0)) % 100)
			const curveFactor = seed / 100 - 0.5
			const curvature = Math.min(dist * 0.25, 70)
			const midX = (sx + tx) / 2 + curveFactor * curvature
			const midY = (sy + ty) / 2 - curvature * 0.6

			// Dot radius with frequency weighting
			const radius = Math.min(2.5 + Math.log2(item.count + 1) * 0.8, 6.5)

			lines.push({
				item,
				sx,
				sy,
				tx,
				ty,
				midX,
				midY,
				color: item.color,
				width: effectLevel >= 3 ? 1.5 : 1.0,
				seed,
				radius,
			})
		}

		const hasGrid = effectLevel >= 1
		const hasPulse = effectLevel >= 2
		const hasParticles = effectLevel >= 3

		const draw = (time: number) => {
			ctx.clearRect(0, 0, width, height)

			// Background
			ctx.fillStyle = "#0a0a0f"
			ctx.fillRect(0, 0, width, height)

			// Apply Camera Transform
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

			// Trajectory Arcs
			for (const line of lines) {
				ctx.strokeStyle = line.color
				ctx.lineWidth = Math.max(0.6 / zoom, 0.4) * line.width
				ctx.globalAlpha = 0.45
				ctx.beginPath()
				ctx.moveTo(line.sx, line.sy)
				ctx.quadraticCurveTo(line.midX, line.midY, line.tx, line.ty)
				ctx.stroke()
				ctx.globalAlpha = 1.0
			}

			// Photon Particle Stream (Level 3 ONLY)
			if (hasParticles && lines.length > 0) {
				for (let i = 0; i < lines.length; i++) {
					const line = lines[i]
					const t = (time / 1600 + line.seed / 100) % 1
					const invT = 1 - t
					const px = invT * invT * line.sx + 2 * invT * t * line.midX + t * t * line.tx
					const py = invT * invT * line.sy + 2 * invT * t * line.midY + t * t * line.ty

					// Glowing head
					ctx.fillStyle = "#ffffff"
					ctx.beginPath()
					ctx.arc(px, py, Math.max(1.8 / zoom, 1.0), 0, Math.PI * 2)
					ctx.fill()
				}
			}

			// Source Attack / Ban Nodes
			for (const line of lines) {
				const r = Math.max(line.radius / zoom, 1.5 / zoom)

				// High frequency halo
				if (line.item.count >= 10 && hasGrid) {
					ctx.fillStyle = line.color
					ctx.globalAlpha = 0.2
					ctx.beginPath()
					ctx.arc(line.sx, line.sy, r * 2.2, 0, Math.PI * 2)
					ctx.fill()
					ctx.globalAlpha = 1.0
				}

				// Center Dot
				ctx.fillStyle = line.color
				ctx.beginPath()
				ctx.arc(line.sx, line.sy, r, 0, Math.PI * 2)
				ctx.fill()

				// LOD Level 1 (Zoom >= 1.8): Display Country Code Badge
				if (zoom >= 1.8 && line.item.country) {
					ctx.font = `600 ${Math.max(8 / zoom, 5)}px monospace`
					ctx.fillStyle = "rgba(255,255,255,0.75)"
					ctx.fillText(line.item.country, line.sx + r + 2 / zoom, line.sy + 2.5 / zoom)
				}

				// LOD Level 2 (Zoom >= 3.5): Display Masked IP
				if (zoom >= 3.5) {
					ctx.font = `${Math.max(7 / zoom, 4.5)}px sans-serif`
					ctx.fillStyle = "rgba(255,255,255,0.45)"
					ctx.fillText(line.item.ip, line.sx + r + 2 / zoom, line.sy + 10 / zoom)
				}
			}

			// Machine Target Markers
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

					// Label (with City on LOD 1)
					const labelText = zoom >= 1.8 && m.city ? `${m.name || m.id} · ${m.city}` : m.name || m.id
					ctx.fillStyle = isSelected
						? "rgba(255,255,255,0.95)"
						: isDim
						? "rgba(255,255,255,0.3)"
						: "rgba(255,255,255,0.75)"
					ctx.font = `${isSelected ? "bold " : ""}${Math.max(10 / zoom, 6)}px sans-serif`
					ctx.fillText(labelText, x + dotR + 3 / zoom, y + 3.5 / zoom)
				}
			}

			ctx.restore()
		}

		// Animation frame loop for Level 2/3, else single static draw
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
		if (e.button !== 0) return // left click only
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

		// Hit-test when not dragging
		const container = containerRef.current
		if (!container || !worldData) return
		const rect = container.getBoundingClientRect()
		const mouseX = e.clientX - rect.left
		const mouseY = e.clientY - rect.top

		const width = rect.width
		const height = rect.height
		const projection = geoEqualEarth().fitSize([width, height], { type: "Sphere" })

		// Check machine markers first
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

		// Check trajectory source points
		const items = mapMode === "attackers" ? events : bans
		for (const item of items) {
			const lat = (item as any).lat
			const lon = (item as any).lon
			if (lat != null && lon != null) {
				const pos = projection([lon, lat])
				if (!pos) continue
				const sx = pos[0] * zoom + pan.x
				const sy = pos[1] * zoom + pan.y
				if (Math.hypot(mouseX - sx, mouseY - sy) <= 9) {
					const isBan = mapMode === "bans"
					const ip = (item as any).ip || (item as any).src_ip
					const country = (item as any).country
					const machineId = item.machine_id
					const type = (item as any).event_type || (item as any).jail
					const count = (item as any).count || (item as any).ban_count || 1
					const ts = (item as any).ts || (item as any).banned_at
					setHovered({
						type: "source",
						title: ip,
						subtitle: [country, (item as any).city].filter(Boolean).join(" · ") || country || "Unknown Location",
						badge: isBan ? `Banned: ${type}` : type,
						badgeColor: isBan ? "bg-red-500/20 text-red-400 border-red-500/30" : "bg-amber-500/20 text-amber-400 border-amber-500/30",
						details: [
							{ label: "Target", val: machineId || "All" },
							{ label: "Hits", val: `× ${count}` },
							{ label: "Time", val: ts ? new Date(ts).toLocaleTimeString() : "Recent" },
						],
						x: mouseX,
						y: mouseY,
					})
					return
				}
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
									<span className="font-mono">{b.ip}</span>
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
