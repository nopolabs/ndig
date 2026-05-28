import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { getNameserver, getCompareValue, fixArgv } from "../ndig.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const NDIG = join(__dirname, "..", "ndig.mjs");

// ---------------------------------------------------------------------------
// getNameserver
// ---------------------------------------------------------------------------

test("getNameserver: resolves known aliases to IPs", () => {
	assert.equal(getNameserver("cloudflare"), "1.1.1.1");
	assert.equal(getNameserver("comodo"), "8.26.56.26");
	assert.equal(getNameserver("google"), "8.8.8.8");
	assert.equal(getNameserver("opendns"), "208.67.222.222");
	assert.equal(getNameserver("quad9"), "9.9.9.9");
	assert.equal(getNameserver("verisign"), "64.6.64.6");
});

test("getNameserver: passes through unknown values unchanged", () => {
	assert.equal(getNameserver("1.2.3.4"), "1.2.3.4");
	assert.equal(getNameserver("ns1.example.com"), "ns1.example.com");
});

// ---------------------------------------------------------------------------
// getCompareValue
// ---------------------------------------------------------------------------

test("getCompareValue: returns 5th field for non-MX types", () => {
	assert.equal(
		getCompareValue("example.com.\t300\tIN\tA\t93.184.216.34", "A"),
		"93.184.216.34",
	);
	assert.equal(
		getCompareValue(
			"example.com.\t300\tIN\tAAAA\t2606:2800:21f:cb07:6820:80da:af6b:8b2c",
			"AAAA",
		),
		"2606:2800:21f:cb07:6820:80da:af6b:8b2c",
	);
	assert.equal(
		getCompareValue(
			"example.com.\t300\tIN\tNS\tns1.example.com.",
			"NS",
		),
		"ns1.example.com.",
	);
});

test("getCompareValue: zero-pads MX priority for correct lexicographic sort", () => {
	// priority 10  → "00010"
	assert.equal(
		getCompareValue(
			"example.com.\t300\tIN\tMX\t10\tmail.example.com.",
			"MX",
		),
		"00010 mail.example.com.",
	);
	// priority 5 → "00005"
	assert.equal(
		getCompareValue(
			"example.com.\t300\tIN\tMX\t5\tmail.example.com.",
			"MX",
		),
		"00005 mail.example.com.",
	);
	// priority 100 → "00100"
	assert.equal(
		getCompareValue(
			"example.com.\t300\tIN\tMX\t100\tmail.example.com.",
			"MX",
		),
		"00100 mail.example.com.",
	);
});

test("getCompareValue: MX sort order is correct (low priority first)", () => {
	const r5 = getCompareValue(
		"example.com.\t300\tIN\tMX\t5\ta.example.com.",
		"MX",
	);
	const r10 = getCompareValue(
		"example.com.\t300\tIN\tMX\t10\tb.example.com.",
		"MX",
	);
	const r100 = getCompareValue(
		"example.com.\t300\tIN\tMX\t100\tc.example.com.",
		"MX",
	);
	assert.ok(r5 < r10, "priority 5 should sort before 10");
	assert.ok(r10 < r100, "priority 10 should sort before 100");
});

// ---------------------------------------------------------------------------
// fixArgv
// ---------------------------------------------------------------------------

test("fixArgv: returns argv unchanged when fewer than 3 elements", () => {
	assert.deepEqual(fixArgv(["node", "ndig.mjs"]), ["node", "ndig.mjs"]);
});

test("fixArgv: returns argv unchanged when -- is already present", () => {
	const argv = ["node", "ndig.mjs", "--", "example.com"];
	assert.deepEqual(fixArgv(argv), argv);
});

test("fixArgv: returns argv unchanged when last arg is a flag", () => {
	for (const flag of ["--help", "-h", "--version", "-V"]) {
		const argv = ["node", "ndig.mjs", flag];
		assert.deepEqual(fixArgv(argv), argv, `should pass through ${flag}`);
	}
});

test("fixArgv: moves last argument after -- separator", () => {
	assert.deepEqual(fixArgv(["node", "ndig.mjs", "example.com"]), [
		"node",
		"ndig.mjs",
		"--",
		"example.com",
	]);
});

test("fixArgv: preserves flags when moving domain after --", () => {
	assert.deepEqual(
		fixArgv(["node", "ndig.mjs", "-t", "A", "example.com"]),
		["node", "ndig.mjs", "-t", "A", "--", "example.com"],
	);
	assert.deepEqual(
		fixArgv(["node", "ndig.mjs", "-n", "google", "-s", "MX", "example.com"]),
		["node", "ndig.mjs", "-n", "google", "-s", "MX", "--", "example.com"],
	);
});

// ---------------------------------------------------------------------------
// CLI integration tests
// ---------------------------------------------------------------------------

test("CLI: --version outputs 1.0.0", () => {
	const { stdout, status } = spawnSync("node", [NDIG, "--version"], {
		encoding: "utf8",
	});
	assert.equal(status, 0);
	assert.match(stdout, /1\.0\.0/);
});

test("CLI: --help exits 0 and shows usage", () => {
	const { stdout, status } = spawnSync("node", [NDIG, "--help"], {
		encoding: "utf8",
	});
	assert.equal(status, 0);
	assert.match(stdout, /ndig/);
	assert.match(stdout, /domain/);
	assert.match(stdout, /Supported types/);
});

test("CLI: missing domain exits non-zero", () => {
	const { status } = spawnSync("node", [NDIG], { encoding: "utf8" });
	assert.notEqual(status, 0);
});

test("CLI: bare label with no dot exits non-zero with error message", () => {
	const { stderr, status } = spawnSync("node", [NDIG, "--", "nopolabs"], {
		encoding: "utf8",
		timeout: 10000,
	});
	assert.notEqual(status, 0);
	assert.match(stderr, /No SOA for "nopolabs"/);
});

test("CLI: -t and -s together exit non-zero", () => {
	const { status } = spawnSync(
		"node",
		[NDIG, "-n", "google", "-t", "A", "-s", "MX", "--", "google.com"],
		{ encoding: "utf8" },
	);
	assert.notEqual(status, 0);
});

test("CLI: queries A records for google.com via Google DNS", () => {
	const { stdout, status } = spawnSync(
		"node",
		[NDIG, "-n", "google", "-t", "A", "--", "google.com"],
		{ encoding: "utf8", timeout: 10000 },
	);
	assert.equal(status, 0);
	assert.match(stdout, /google\.com\.\s+\d+\s+IN\s+A\s+\d+\.\d+\.\d+\.\d+/);
});

test("CLI: -s (short) strips the first four fields", () => {
	const { stdout, status } = spawnSync(
		"node",
		[NDIG, "-n", "google", "-s", "A", "--", "google.com"],
		{ encoding: "utf8", timeout: 10000 },
	);
	assert.equal(status, 0);
	// Short output should be just the IP address, no domain/ttl/class/type prefix
	const lines = stdout.trim().split("\n");
	assert.ok(lines.length > 0);
	for (const line of lines) {
		assert.match(line, /^\d+\.\d+\.\d+\.\d+$/);
	}
});
