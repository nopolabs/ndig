#! /usr/bin/env node

// from https://stackoverflow.com/questions/19322962/how-can-i-list-all-dns-records

import { Command } from 'commander';
import { $, chalk } from 'zx';

$.verbose = false;

// A (Host address)
// AAAA (IPv6 host address)
// ALIAS (Auto resolved alias)
// CNAME (Canonical name for an alias)
// MX (Mail eXchange)
// NS (Name Server)
// PTR (Pointer)
// SOA (Start Of Authority)
// SRV (location of service)
// TXT (Descriptive text)

const ALL_TYPES = ['A', 'AAAA', 'ALIAS', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT'];

function exitWithError(errorMessage) {
	console.error(chalk.red(errorMessage));
	process.exit(1);
}

async function getAuthoritativeNameServer(domain) {
	const result = await $`dig +short -t "SOA" "${domain}"`
	const soa = result.stdout.split('. ')[0];
	if (soa) {
		return soa;
	}
	exitWithError(`No SOA for "${domain}"`);
}

async function getRecords(ns, domain, type) {
	// console.log(`dig +noall +answer -t "${type}" "${ns}" "${domain}"`);
	const records = await $`dig +noall +answer -t "${type}" "${ns}" "${domain}"`;
	return  records.stdout.trim().split(/\r?\n/)
		.filter(line => line.startsWith(domain + ".\t"));
}

async function getA(ns, domain) {
	return await getRecords(ns, domain, 'A');
}

async function getSOA(ns, domain) {
	return await getRecords(ns, domain, 'SOA');
}

async function getAll(ns, domain, types) {
	types = types.map(t => t.toUpperCase());
	if (types.includes('ALL') || types.includes('ANY')) {
		types = ALL_TYPES;
	}
	const all = new Map();
	for (const type of types) {
		let records = await getRecords(ns, domain, type);
		all.set(type, records);
	}
	return all;
}

async function dig(domain, options) {
	if (options.type && options.short) {
		exitWithError("only one of -t and -s allowed")
	}
	const types = options.type ? options.type : options.short ? options.short : ['ALL'];
	const ns = await getAuthoritativeNameServer(domain)
	const recordsMap = await getAll(ns, domain, types);
	const format = options.short
		? (record, type) => record.replace(/^\S+\s+\S+\s+\S+\s+\S+\s+/, '')
		: (record, type) => record;
	recordsMap.forEach((records, type) => {
		records.forEach(record => console.log(format(record, type)));
	});
}

const program = new Command()
	.name('jdig')
	.version('0.0.1')
	.description('Get DNS records using dig')
	.addHelpText('after', "\nSupported types: " + ALL_TYPES.join(', ') + ", or ALL")
	.addHelpCommand(true)
	.helpOption(true)
	.option('-t, --type [type...]', 'record type')
	.option('-s, --short [type...]', 'record type (short output)')
	.argument('<domain>', 'domain')
	.action(dig);

function fixArgv(argv) {
	if (argv.includes('--') || argv.includes('--help') || argv.includes('--h')) {
		return argv;
	}
	const domain = argv.slice(-1);
	const rest = argv.slice(0, -1);
	return rest.concat('--', domain);
}

const argv = fixArgv(process.argv)

await program.parseAsync(argv);
