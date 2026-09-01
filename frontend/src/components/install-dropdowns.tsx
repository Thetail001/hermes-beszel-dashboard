import { i18n } from "@lingui/core"
import { memo } from "react"
import { copyToClipboard, getHubURL } from "@/lib/utils"
import { DropdownMenuContent, DropdownMenuItem } from "./ui/dropdown-menu"

// const isbeta = beszel.hub_version.includes("beta")
// const imagetag = isbeta ? ":edge" : ""

/**
 * Get the URL of the script to install the agent.
 * @param path - The path to the script (e.g. "/brew").
 * @returns The URL for the script.
 */
const getScriptUrl = (path: string = "") => {
	return `https://get.beszel.dev${path}`
	// no beta for now
	// const url = new URL("https://get.beszel.dev")
	// url.pathname = path
	// if (isBeta) {
	// 	url.searchParams.set("beta", "1")
	// }
	// return url.toString()
}

export function copyDockerCompose(port = "45876", publicKey: string, token: string) {
	copyToClipboard(`services:
  beszel-agent:
    image: henrygd/beszel-agent
    container_name: beszel-agent
    restart: unless-stopped
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./beszel_agent_data:/var/lib/beszel-agent
      # monitor other disks / partitions by mounting a folder in /extra-filesystems
      # - /mnt/disk/.beszel:/extra-filesystems/sda1:ro
    environment:
      LISTEN: ${port}
      KEY: '${publicKey}'
      TOKEN: ${token}
      HUB_URL: ${getHubURL()}`)
}

export function copyDockerRun(port = "45876", publicKey: string, token: string) {
	copyToClipboard(
		`docker run -d --name beszel-agent --network host --restart unless-stopped -v /var/run/docker.sock:/var/run/docker.sock:ro -v beszel_agent_data:/var/lib/beszel-agent -e KEY="${publicKey}" -e LISTEN=${port} -e TOKEN="${token}" -e HUB_URL="${getHubURL()}" henrygd/beszel-agent`
	)
}

export function copyLinuxCommand(port = "45876", publicKey: string, token: string, variant: "linux" | "brew" | "freebsd" = "linux") {
	// Linux：本项目命令 —— beszel agent + security-collector 一步装
	if (variant === "linux") {
		// security ingest 挂在 hermes 面板同 origin 下（iframe 是相对路径加载，
		// 所以 window.location.origin 就是 hermes dashboard 的公网地址）
		const centerUrl = `${window.location.origin}/api/plugins/beszel/security/ingest`
		let cmd = `curl -fsSL https://raw.githubusercontent.com/Thetail001/hermes-beszel-dashboard/master/agent/install-agent.sh | bash -s -- -p ${port} -k "${publicKey}" -t "${token}" -url "${getHubURL()}" -center "${centerUrl}"`
		if ((i18n.locale + navigator.language).includes("zh-CN")) {
			cmd += ` --china-mirrors`
		}
		copyToClipboard(cmd)
		return
	}
	// brew / freebsd：官方脚本（security-collector 是 Linux 探针，这些平台只装 beszel agent）
	let cmd = `curl -sL ${getScriptUrl(
		variant === "brew" ? "/brew" : ""
	)} -o /tmp/install-agent.sh && chmod +x /tmp/install-agent.sh && /tmp/install-agent.sh -p ${port} -k "${publicKey}" -t "${token}" -url "${getHubURL()}"`
	// brew script does not support --china-mirrors
	if (variant !== "brew" && (i18n.locale + navigator.language).includes("zh-CN")) {
		cmd += ` --china-mirrors`
	}
	copyToClipboard(cmd)
}

export function copyWindowsCommand(port = "45876", publicKey: string, token: string) {
	copyToClipboard(
		`& iwr -useb ${getScriptUrl()} -OutFile "$env:TEMP\\install-agent.ps1"; & Powershell -ExecutionPolicy Bypass -File "$env:TEMP\\install-agent.ps1" -Key "${publicKey}" -Port ${port} -Token "${token}" -Url "${getHubURL()}"`
	)
}

export interface DropdownItem {
	text: string
	onClick?: () => void
	url?: string
	icons?: React.ComponentType<React.SVGProps<SVGSVGElement>>[]
}

export const InstallDropdown = memo(({ items }: { items: DropdownItem[] }) => {
	return (
		<DropdownMenuContent align="end">
			{items.map((item, index) => {
				const className = "cursor-pointer flex items-center gap-1.5"
				return item.url ? (
					<DropdownMenuItem key={index} asChild>
						<a href={item.url} className={className} target="_blank" rel="noopener noreferrer">
							{item.text}{" "}
							{item.icons?.map((Icon, iconIndex) => (
								<Icon key={iconIndex} className="size-4" />
							))}
						</a>
					</DropdownMenuItem>
				) : (
					<DropdownMenuItem key={index} onClick={item.onClick} className={className}>
						{item.text}{" "}
						{item.icons?.map((Icon, iconIndex) => (
							<Icon key={iconIndex} className="size-4" />
						))}
					</DropdownMenuItem>
				)
			})}
		</DropdownMenuContent>
	)
})
