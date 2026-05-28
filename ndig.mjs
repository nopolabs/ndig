#! /usr/bin/env node

// from https://stackoverflow.com/questions/19322962/how-can-i-list-all-dns-records

import { Command } from "commander";
import { $, chalk } from "zx";
import { fileURLToPath } from "node:url";
import { realpathSync } from "node:fs";

$.verbose = false;

// A (Host address)
// AAAA (IPv6 host address)
// CNAME (Canonical name for an alias)
// MX (Mail eXchange)
// NS (Name Server)
// PTR (Pointer)
// SOA (Start Of Authority)
// SRV (location of service)
// TXT (Descriptive text)
// RRSIG (DNSSEC signature)
// DNSKEY (DNSSEC public key)
// DS (DNSSEC public key hash)
// NSEC (DNSSEC denial-of-existence)
// NSEC3 (DNSSEC denial-of-existence)
// CDNSKEY (DNSSEC child zone public key)
// CDS (DNSSEC child zone public key hash)

const DNSSEC_TYPES = ["RRSIG", "DNSKEY", "DS", "NSEC", "NSEC3", "CDNSKEY", "CDS"];
const ALL_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT"].concat(DNSSEC_TYPES);

function exitWithError(errorMessage) {
	console.error(chalk.red(errorMessage));
	process.exit(1);
}

async function getAuthoritativeNameServer(domain) {
	try {
		const result = await $`dig +short -t "SOA" "${domain}"`;
		return result.stdout.split(". ")[0];
	} catch (e) {
		exitWithError(`dig failed while looking up SOA for "${domain}": ${e.message}`);
	}
}

async function recursiveAuthoritativeNameServer(domain, candidate) {
	const soa = await getAuthoritativeNameServer(candidate);
	if (soa) {
		console.log("Zone: " + candidate);
		return soa;
	}
	const parent = candidate.match(/[^.]+\.(.+)/)[1];
	if (parent === candidate) {
		exitWithError(`No SOA for "${domain}"`);
	}
	return await recursiveAuthoritativeNameServer(domain, parent);
}

async function findAuthoritativeNameServer(domain) {
	const soa = await recursiveAuthoritativeNameServer(domain, domain);
	if (!soa) {
		const parent = domain.split(".", 2)[0];
		if (parent === domain) {
			exitWithError(`No SOA for "${domain}"`);
		}
	}
	return soa;
}

async function getRecords(ns, domain, type) {
	try {
		const records = await $`dig +noall +answer -t "${type}" "@${ns}" "${domain}"`;
		return records.stdout
			.trim()
			.split(/\r?\n/)
			.filter(
				(line) =>
					line.startsWith(domain + ".\t") || line.startsWith(domain + ". "),
			);
	} catch (e) {
		exitWithError(`dig failed for ${type} ${domain} @${ns}: ${e.message}`);
	}
}

async function getAll(ns, domain, types) {
	const normalized = types.map((t) => t.toUpperCase());
	let expanded;
	if (normalized.includes("ALL") || normalized.includes("ANY")) {
		expanded = ALL_TYPES;
	} else if (normalized.includes("DNSSEC")) {
		expanded = [...new Set(normalized.filter((t) => t !== "DNSSEC").concat(DNSSEC_TYPES))];
	} else {
		expanded = normalized;
	}
	const all = new Map();
	for (const type of expanded) {
		const records = await getRecords(ns, domain, type);
		all.set(type, records);
	}
	return all;
}

function getNameserver(nameserver) {
	switch (nameserver) {
		case "cloudflare":
			return "1.1.1.1";
		case "comodo":
			return "8.26.56.26";
		case "google":
			return "8.8.8.8";
		case "opendns":
			return "208.67.222.222";
		case "quad9":
			return "9.9.9.9";
		case "verisign":
			return "64.6.64.6";
		default:
			return nameserver;
	}
}

function getCompareValue(record, type) {
	const fields = record.split(/\s+/);
	if (type === "MX") {
		const priority = "0000" + fields[4];
		return priority.substring(priority.length - 5) + " " + fields[5];
	}
	return fields[4];
}

async function dig(domain, options) {
	$.verbose = !!options.verbose;
	if (options.type && options.short) {
		exitWithError("only one of -t and -s allowed");
	}
	const types = options.type
		? options.type
		: options.short
			? options.short
			: ["ALL"];
	const ns = options.nameserver
		? getNameserver(options.nameserver)
		: await findAuthoritativeNameServer(domain);
	const recordsMap = await getAll(ns, domain, types);
	const format = options.short
		? (record) => record.replace(/^\S+\s+\S+\s+\S+\s+\S+\s+/, "")
		: (record) => record;
	recordsMap.forEach((records, type) => {
		if (!options.unsorted) {
			records.sort((a, b) => {
				// compare the 5th field of each record
				const av = getCompareValue(a, type);
				const bv = getCompareValue(b, type);
				if (av < bv) {
					return -1;
				}
				if (av > bv) {
					return 1;
				}
				return 0;
			});
		}
		records.forEach((record) => console.log(format(record)));
	});
}

const program = new Command()
	.name("ndig")
	.version("1.0.0")
	.description("Get DNS records using dig")
	.addHelpText(
		"after",
		"\nSupported types: " + ALL_TYPES.join(", ") + ", or ALL, or DNSSEC",
	)
	.addHelpCommand(true)
	.helpOption(true)
	.option("-v, --verbose", "verbose output")
	.option("-u, --unsorted", "unsorted output")
	.option(
		"-n, --nameserver [nameserver]",
		"nameserver to query (default is SOA)",
	)
	.option("-t, --type [type...]", "record type")
	.option("-s, --short [type...]", "record type (short output)")
	.argument("<domain>", "domain")
	.action(dig);

function fixArgv(argv) {
	// Leave argv alone when there's nothing to rearrange, when the caller
	// already added a -- separator, or when the last argument is a flag
	// (e.g. --version, -V, --help, -h) that commander handles directly.
	// Valid DNS names never start with '-', so this check is always safe.
	if (argv.length < 3 || argv.includes("--") || argv.at(-1).startsWith("-")) {
		return argv;
	}
	const domain = argv.slice(-1);
	const rest = argv.slice(0, -1);
	return rest.concat("--", domain);
}

export { getNameserver, getCompareValue, fixArgv };

if (realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
	program.parse(fixArgv(process.argv));
}
