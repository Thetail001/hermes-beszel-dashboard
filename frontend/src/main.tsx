import "./index.css"
// [beszel patch] "History trap": inside the Hermes plugin iframe the
// session history is shared with the host dashboard SPA. Pushing a sentinel
// entry and bouncing popstate back forward keeps the browser back button
// from unmounting the plugin tab (iframe disappears → blank page).
;(function () {
	if (!window.parent || window.parent === window) return // not in iframe
	history.pushState({ sentinel: true }, "", location.href)
	window.addEventListener("popstate", function () {
		// user pressed back past our sentinel — bounce forward again
		if (!history.state || !history.state.sentinel) {
			history.forward()
		}
	})
})()
import { i18n } from "@lingui/core"
import { I18nProvider } from "@lingui/react"
import { useStore } from "@nanostores/react"
import { DirectionProvider } from "@radix-ui/react-direction"
// import { Suspense, lazy, useEffect, StrictMode } from "react"
import { lazy, memo, Suspense, useEffect } from "react"
import ReactDOM from "react-dom/client"
import Navbar from "@/components/navbar.tsx"
import { $router } from "@/components/router.tsx"
import Settings from "@/components/routes/settings/layout.tsx"
import { ThemeProvider } from "@/components/theme-provider.tsx"
import { Toaster } from "@/components/ui/toaster.tsx"
import { alertManager } from "@/lib/alerts"
import { isAdmin, pb, updateUserSettings } from "@/lib/api.ts"
import { dynamicActivate, getLocale } from "@/lib/i18n"
import {
	$authenticated,
	$copyContent,
	$direction,
	$newVersion,
	$publicKey,
	$userSettings,
	defaultLayoutWidth,
} from "@/lib/stores.ts"
import * as systemsManager from "@/lib/systemsManager.ts"
import type { BeszelInfo, UpdateInfo } from "./types"

const LoginPage = lazy(() => import("@/components/login/login.tsx"))
const Home = lazy(() => import("@/components/routes/home.tsx"))
const Containers = lazy(() => import("@/components/routes/containers.tsx"))
const Smart = lazy(() => import("@/components/routes/smart.tsx"))
const SystemDetail = lazy(() => import("@/components/routes/system.tsx"))
const Security = lazy(() => import("@/components/routes/security.tsx"))
const CopyToClipboardDialog = lazy(() => import("@/components/copy-to-clipboard.tsx"))

const App = memo(() => {
	const page = useStore($router)

	useEffect(() => {
		// change auth store on auth change
		const unsubscribeAuth = pb.authStore.onChange(() => {
			$authenticated.set(pb.authStore.isValid)
		})
		// get general info for authenticated users, such as public key and version
		pb.send<BeszelInfo>("/api/beszel/info", {}).then((data) => {
			$publicKey.set(data.key)
			// check for updates if enabled
			if (data.cu && isAdmin()) {
				pb.send<UpdateInfo>("/api/beszel/update", {}).then($newVersion.set)
			}
		})
		// get user settings
		updateUserSettings()
		// need to get system list before alerts
		systemsManager.init()
		systemsManager
			// get current systems list
			.refresh()
			// subscribe to new system updates
			.then(systemsManager.subscribe)
			// get current alerts
			.then(alertManager.refresh)
			// subscribe to new alert updates
			.then(alertManager.subscribe)
		return () => {
			unsubscribeAuth()
			alertManager.unsubscribe()
			systemsManager.unsubscribe()
		}
	}, [])

	if (!page) {
		// [beszel patch] Inside the Hermes plugin iframe the pathname never
		// matches the router's routes — fall back to home instead of 404.
		return <Home />
	} else if (page.route === "home") {
		return <Home />
	} else if (page.route === "system") {
		return <SystemDetail id={page.params.id} />
	} else if (page.route === "containers") {
		return <Containers />
	} else if (page.route === "smart") {
		return <Smart />
	} else if (page.route === "settings") {
		return <Settings />
	} else if (page.route === "security") {
		return <Security />
	}
})

const Layout = () => {
	const authenticated = useStore($authenticated)
	const copyContent = useStore($copyContent)
	const direction = useStore($direction)
	const { layoutWidth } = useStore($userSettings, { keys: ["layoutWidth"] })

	useEffect(() => {
		document.documentElement.dir = direction
	}, [direction])

	return (
		<DirectionProvider dir={direction}>
			{!authenticated ? (
				<Suspense>
					<LoginPage />
				</Suspense>
			) : (
				<div style={{ "--container": `${layoutWidth ?? defaultLayoutWidth}px` } as React.CSSProperties}>
					<div className="container">
						<Navbar />
					</div>
					<div className="container relative">
						<Suspense>
							<App />
						</Suspense>
						{copyContent && (
							<Suspense>
								<CopyToClipboardDialog content={copyContent} />
							</Suspense>
						)}
					</div>
				</div>
			)}
		</DirectionProvider>
	)
}

const I18nApp = () => {
	useEffect(() => {
		// [beszel patch] Auto-login: fetch a session token from the Hermes
		// plugin backend (which holds the real credentials), then load it into
		// the PocketBase authStore. The beszel login page never renders.
		if (!pb.authStore.isValid) {
			fetch("/api/plugins/beszel/auto-auth", { credentials: "include" })
				.then((r) => (r.ok ? r.json() : Promise.reject(r.status)))
				.then(({ token, record }) => {
					pb.authStore.save(token, record)
					// authStore.onChange listeners live inside <App>, which is not
					// mounted yet while the login page shows — flip the atom directly.
					$authenticated.set(true)
				})
				.catch((err) => {
					console.warn("[beszel] auto-login failed:", err)
				})
		}
	}, [])
	useEffect(() => {
		dynamicActivate(getLocale())
	}, [])

	return (
		<I18nProvider i18n={i18n}>
			<ThemeProvider>
				<Layout />
				<Toaster />
			</ThemeProvider>
		</I18nProvider>
	)
}

ReactDOM.createRoot(document.getElementById("app") as HTMLElement).render(
	// strict mode in dev mounts / unmounts components twice
	// and breaks the clipboard dialog
	//<StrictMode>
	<I18nApp />
	//</StrictMode>
)
