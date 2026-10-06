import { loadConfigFromEnv } from "./config.js";
import { buildServer, resolveSession } from "./server.js";

async function start(): Promise<void> {
	const config = loadConfigFromEnv();
	const server = buildServer(config);
	await server.listen({
		host: config.host,
		port: config.port,
	});
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1])) {
	start().catch(() => {
		process.exit(1);
	});
}

export { buildServer, loadConfigFromEnv, resolveSession };
