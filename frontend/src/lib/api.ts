import { t } from "@lingui/core/macro"
import PocketBase from "pocketbase"
import { basePath } from "@/components/router"
import { toast } from "@/components/ui/use-toast"
import type { ChartTimes, UserSettings } from "@/types"
import { $alerts, $allSystemsById, $allSystemsByName, $userSettings } from "./stores"
import { chartTimeData } from "./utils"

/** PocketBase JS Client */
export const pb = new PocketBase(basePath)

export const isAdmin = () => pb.authStore.record?.role === "admin"
export const isReadOnlyUser = () => pb.authStore.record?.role === "readonly"

export const verifyAuth = () => {
	// [beszel patch] Token comes from the Hermes plugin backend's
	// auto-auth (regular users collection). On refresh failure, re-fetch a
	// fresh token from the backend instead of logging out — the token can go
	// stale server-side while still looking valid locally, which blanked the
	// systems list after a few navigation clicks.
	pb.collection("users")
		.authRefresh()
		.catch(() => {
			fetch("/api/plugins/beszel/auto-auth", { credentials: "include" })
				.then((r) => (r.ok ? r.json() : Promise.reject(r.status)))
				.then(({ token, record }) => {
					pb.authStore.save(token, record)
					systemsManager.refresh()
				})
				.catch(() => {
					logOut()
					toast({
						title: t`Failed to authenticate`,
						description: t`Please log in again`,
						variant: "destructive",
					})
				})
		})
}

/** Logs the user out by clearing the auth store and unsubscribing from realtime updates. */
export function logOut() {
	$allSystemsByName.set({})
	$allSystemsById.set({})
	$alerts.set({})
	$userSettings.set({} as UserSettings)
	sessionStorage.setItem("lo", "t") // prevent auto login on logout
	pb.authStore.clear()
	pb.realtime.unsubscribe()
}

/** Fetch or create user settings in database */
export async function updateUserSettings() {
	try {
		const req = await pb.collection("user_settings").getFirstListItem("", { fields: "settings" })
		$userSettings.set(req.settings)
		return
	} catch (e) {
		console.error("get settings", e)
	}
	// create user settings if error fetching existing
	try {
		const createdSettings = await pb.collection("user_settings").create({ user: pb.authStore.record?.id })
		$userSettings.set(createdSettings.settings)
	} catch (e) {
		console.error("create settings", e)
	}
}

export function getPbTimestamp(timeString: ChartTimes, d?: Date) {
	d ||= chartTimeData[timeString].getOffset(new Date())
	const year = d.getUTCFullYear()
	const month = String(d.getUTCMonth() + 1).padStart(2, "0")
	const day = String(d.getUTCDate()).padStart(2, "0")
	const hours = String(d.getUTCHours()).padStart(2, "0")
	const minutes = String(d.getUTCMinutes()).padStart(2, "0")
	const seconds = String(d.getUTCSeconds()).padStart(2, "0")

	return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`
}
