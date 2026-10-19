// scripts/build.mjs
//
// The fork's build. No cmake, no autotools: one node script, three targets.
//
//   --lib      lib/*.c              → build/lib/<config>/libngtcp2.a
//   --crypto   crypto/cvmcrypt/*.c  → objects, our backend
//   --tests    tests/*.c + munit    → build/bin/ngtcp2-tests, links the archive
//
// Why this exists instead of CMake: the fork carries exactly one addition
// (crypto/cvmcrypt/) and upstream's CMake files are a moving target we would
// have to re-patch on every rebase. Compiling 46 files from a list is not
// worth a second build system.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { parseArgs, help } from "./lib/args.mjs";
import { logger, mkdirp, rmrf, collect } from "./lib/util.mjs";
import { discover } from "./lib/toolchain.mjs";
import { flagsFor, sanitizerFlags } from "./lib/flags.mjs";
import { compile, link, objectPath } from "./lib/cc.mjs";
import { runOrDie } from "./lib/exec.mjs";
import { ensureVersionHeader } from "./lib/version.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const BUILD = path.join(ROOT, "build");

const ui = logger("build");
const opts = parseArgs(process.argv.slice(2));

if (process.argv.includes("--help") || process.argv.includes("-h")) {
    console.log(help.usage);
    for (const o of help.options) console.log(`  ${o}`);
    process.exit(0);
}

/* `node scripts/build.mjs` with no target flag builds everything: a bare
 * invocation should never silently do nothing. */
if (!opts.lib && !opts.tests && !opts.crypto && !opts.clean) {
    opts.lib = opts.tests = opts.crypto = true;
}

function buildOne({ src, tier, tests = false, toolchain }) {
    const obj = objectPath({
        root: ROOT,
        buildDir: BUILD,
        config: opts.config,
        flavor: tier,
        src,
    });
    return compile({
        src,
        obj,
        flags: flagsFor({ tier, opts, root: ROOT, buildDir: BUILD, tests }),
        toolchain,
        verbose: opts.verbose,
        ui,
    });
}

function buildLib(toolchain) {
    const srcs = collect(path.join(ROOT, "lib"), [".c"]);
    const objs = srcs.map((src) => buildOne({ src, tier: "upstream", toolchain }));

    const outDir = path.join(BUILD, "lib", opts.config);
    mkdirp(outDir);
    const archive = path.join(outDir, "libngtcp2.a");
    fs.rmSync(archive, { force: true });
    runOrDie("ar", ["rcs", archive, ...objs], {
        verbose: opts.verbose,
        ui,
        what: "ar libngtcp2.a",
    });

    ui.log(`lib: ${objs.length} object(s) → ${path.relative(ROOT, archive)}`);
    return archive;
}

function buildCrypto(toolchain) {
    const dir = path.join(ROOT, "crypto", "cvmcrypt");
    /* Exclude the test translation unit: it needs munit and is built and run
     * by scripts/crypto-test.mjs instead. */
    const srcs = collect(dir, [".c"]).filter((f) => !f.endsWith("_test.c"));
    if (srcs.length === 0) {
        ui.log("crypto: no sources yet (crypto/cvmcrypt/)");
        return [];
    }
    const objs = srcs.map((src) => buildOne({ src, tier: "ours", toolchain }));
    ui.log(`crypto: ${objs.length} object(s)`);
    return objs;
}

function buildTests(toolchain, libArchive) {
    const binDir = path.join(BUILD, "bin");
    rmrf(binDir);
    mkdirp(binDir);

    /* The test sources are whatever upstream puts directly in tests/, plus
     * munit. A glob rather than a list: a new upstream test file must not be
     * silently skipped by a stale manifest.
     *
     * Top level only. tests/munit/ also holds example.c, which has its own
     * main(), and a recursive glob drags it in — the first build of this
     * script failed exactly that way, with fourteen duplicate symbols. */
    const testsDir = path.join(ROOT, "tests");
    const srcs = fs
        .readdirSync(testsDir)
        .filter((f) => f.endsWith(".c"))
        .sort()
        .map((f) => path.join(testsDir, f));
    srcs.push(path.join(testsDir, "munit", "munit.c"));

    const objs = srcs.map((src) => buildOne({ src, tier: "upstream", tests: true, toolchain }));

    const bin = path.join(binDir, "ngtcp2-tests");
    link({
        /*
         * Upstream tests test lib/, and nothing else. They must not link
         * crypto/cvmcrypt: that object pulls in the whole of cvmcrypt, which
         * lives in another checkout. The backend gets its own binary.
         */
        objs,
        out: bin,
        toolchain,
        libs: [libArchive],
        flags: sanitizerFlags(opts),
        verbose: opts.verbose,
        ui,
    });

    ui.log(`tests: ${objs.length} object(s) → ${path.relative(ROOT, bin)}`);
    return bin;
}

function main() {
    if (opts.clean) {
        rmrf(BUILD);
        ui.log("cleaned build/");
        return;
    }

    const toolchain = discover();
    ui.log(
        `toolchain: ${toolchain.cc}${toolchain.isClang ? " (clang)" : ""}` +
            `${toolchain.ccache ? " + ccache" : ""} · config=${opts.config}`,
    );

    mkdirp(BUILD);
    fs.writeFileSync(
        path.join(BUILD, "config.json"),
        JSON.stringify({ sanitizer: opts.sanitizer, config: opts.config }) + "\n",
    );

    const { version } = ensureVersionHeader({ root: ROOT, buildDir: BUILD, ui });

    const libArchive = opts.lib ? buildLib(toolchain) : null;
    if (opts.crypto) buildCrypto(toolchain);

    if (opts.tests) {
        if (!libArchive) {
            ui.fatal("--tests needs --lib (the archive must exist first)");
        }
        buildTests(toolchain, libArchive);
    }

    ui.log(`done (ngtcp2 ${version})`);
}

main();
