import { loadConfigFromEnv } from "./config.js";
import { buildServer, resolveSession, sweepDeliveries } from "./server.js";

type StartupErrorWriter =
	| { write(chunk: string): unknown }
	| ((chunk: string) => unknown);

function reportStartupError(
	err: unknown,
	writer: StartupErrorWriter = (chunk: string) => process.stderr.write(chunk),
): number {
	let message = err instanceof Error ? err.message : String(err);
	const token = process.env.BROKR_JOIN_TOKEN;
	if (token && token.length > 0 && message.includes(token)) {
		message = message.replaceAll(token, "[REDACTED]");
	}
	const line = `brokr: ${message}\n`;
	if (typeof writer === "function") {
		writer(line);
	} else {
		writer.write(line);
	}
	return 1;
}

async function start(): Promise<void> {
	const config = loadConfigFromEnv();
	const server = buildServer(config);
	await server.listen({
		host: config.host,
		port: config.port,
	});
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1])) {
	start().catch((err: unknown) => {
		process.exit(
			reportStartupError(err, (chunk) => process.stderr.write(chunk)),
		);
	});
}

export {
	buildServer,
	loadConfigFromEnv,
	reportStartupError,
	resolveSession,
	sweepDeliveries,
	type StartupErrorWriter,
};
