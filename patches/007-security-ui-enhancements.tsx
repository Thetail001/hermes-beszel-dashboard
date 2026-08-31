import { Trans } from "@lingui/react/macro"
import { useEffect, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Badge } from "@/components/ui/badge"

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

// ---------------------------------------------------------------- helpers
const EVENT_COLORS: Record<string, string> = {
	ban: "bg-red-500/10 text-red-500 border-red-500/20",
	unban: "bg-green-500/10 text-green-500 border-green-500/20",
	attack: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
	scan: "bg-blue-500/10 text-blue-500 border-blue-500/20",
}

const TYPE_COLORS: Record<string, string> = {
	ban: "#ef4444",
	unban: "#22c55e",
	attack: "#eab308",
	scan: "#3b82f6",
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
						<span className="capitalize">{type}</span>
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

// ---------------------------------------------------------------- component
export default function SecurityPage() {
	const [events, setEvents] = useState<SecurityEvent[]>([])
	const [bans, setBans] = useState<Ban[]>([])
	const [summary, setSummary] = useState<Summary | null>(null)
	const [loading, setLoading] = useState(true)

	useEffect(() => {
		Promise.all([
			fetch("/api/plugins/beszel/security/events?limit=50").then((r) => r.json()),
			fetch("/api/plugins/beszel/security/bans/current").then((r) => r.json()),
			fetch("/api/plugins/beszel/security/stats/summary?period=24h").then((r) => r.json()),
		])
			.then(([ev, bn, sm]) => {
				setEvents(ev.items || [])
				setBans(bn.items || [])
				setSummary(sm)
			})
			.finally(() => setLoading(false))
	}, [])

	return (
		<div className="space-y-4">
			<div className="flex items-center justify-between">
				<h1 className="text-2xl font-semibold tracking-tight">
					<Trans>Security</Trans>
				</h1>
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
						<Table>
							<TableHeader>
								<TableRow>
									<TableHead>
										<Trans>IP</Trans>
									</TableHead>
									<TableHead>
										<Trans>Jail</Trans>
									</TableHead>
									<TableHead>
										<Trans>Banned</Trans>
									</TableHead>
								</TableRow>
							</TableHeader>
							<TableBody>
								{bans.map((b) => (
									<TableRow key={b.id}>
										<TableCell className="font-mono">{b.ip}</TableCell>
										<TableCell>
											<Badge variant="outline">{b.jail}</Badge>
										</TableCell>
										<TableCell>{timeAgo(b.banned_at)}</TableCell>
									</TableRow>
								))}
							</TableBody>
						</Table>
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
										{ev.event_type}
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
