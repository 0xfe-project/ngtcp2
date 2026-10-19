// scripts/quic-interop.mjs
//
// Build and run the cvmcrypt QUIC client against an external server.
//
// This is the only check that the backend actually interoperates. Everything
// else — the KAT, the link test — proves the pieces are individually right;
// this proves they compose into a handshake another implementation accepts.
//
//	# terminal 1
//	/path/to/gointerop -mode=quic-server -addr=127.0.0.1:0 \
//	    -cert=... -key=...
//	# terminal 2
//	node scripts/quic-interop.mjs 127.0.0.1 <port>
//
// The reference server is tests/e2e/gointerop in cvmsockets (quic-go). It
// echoes 4-byte-length-prefixed frames on ALPN "cvmsockets-echo", which is
// what crypto/cvmcrypt/quic_interop.c speaks.

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { logger, mkdirp, collect } from "./lib/util.mjs";
import { discover, freestandingInclude } from "./lib/toolchain.mjs";
import { runOrDie, run } from "./lib/exec.mjs";
import { ensureVersionHeader } from "./lib/version.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const BUILD = path.join(ROOT, "build");
const ui = logger("quic-interop");

const CVMCRYPT = path.resolve(process.env.CVMCRYPT_DIR || path.join(ROOT, "..", "cvmcrypt"));
if (!fs.existsSync(path.join(CVMCRYPT, "include", "cvmcrypt", "cvmcrypt.h"))) {
    ui.fatal(`cvmcrypt not found at ${CVMCRYPT} (set CVMCRYPT_DIR)`);
}

const host = process.argv[2];
const port = process.argv[3];
if (!host || !port) {
    ui.fatal("usage: node scripts/quic-interop.mjs <host> <port>");
}

function buildHarness() {
    const toolchain = discover();
    mkdirp(BUILD);
    ensureVersionHeader({ root: ROOT, buildDir: BUILD, ui });

    const gen = path.join(BUILD, "gen", "include");
    const inc = [
        "-I", gen,
        "-I", path.join(ROOT, "lib", "includes"),
        "-I", path.join(ROOT, "lib"),
        "-I", path.join(ROOT, "crypto", "includes"),
        "-I", path.join(ROOT, "crypto"),
        "-I", path.join(CVMCRYPT, "include"),
        "-I", path.join(CVMCRYPT, "src"),
        "-I", path.join(CVMCRYPT, "vendor", "cvm", "rt"),
    ];

    /* cvmcrypt, compiled the way its own build does: freestanding. */
    const cryObjs = [];
    const objDir = path.join(BUILD, "obj", "debug", "cvmcrypt-lib");
    for (const src of collect(path.join(CVMCRYPT, "src"), [".c", ".S"])) {
        const obj = path.join(objDir, path.relative(CVMCRYPT, src) + ".o");
        mkdirp(path.dirname(obj));
        runOrDie(
            toolchain.cc,
            [
                "-std=c11", "-w", "-g", "-O1",
                "-ffreestanding", "-nostdinc", "-fno-stack-protector",
                ...freestandingInclude(toolchain.cc, toolchain.isClang),
                ...inc,
                "-c", src, "-o", obj,
            ],
            { ui, what: `compile ${path.relative(CVMCRYPT, src)}` },
        );
        cryObjs.push(obj);
    }

    const binDir = path.join(BUILD, "bin");
    mkdirp(binDir);
    const bin = path.join(binDir, "quic-interop");

    runOrDie(
        toolchain.cc,
        [
            "-std=c11", "-w", "-g", "-O1",
            ...inc,
            path.join(ROOT, "crypto", "cvmcrypt", "quic_interop.c"),
            path.join(ROOT, "crypto", "cvmcrypt", "cvmcrypt.c"),
            path.join(ROOT, "crypto", "shared.c"),
            path.join(CVMCRYPT, "tests", "support", "rt_stub.c"),
            ...cryObjs,
            path.join(BUILD, "lib", "debug", "libngtcp2.a"),
            "-o", bin,
        ],
        { ui, what: "link quic-interop" },
    );

    return bin;
}

const bin = buildHarness();
ui.log(`running against ${host}:${port}`);

const r = run(bin, [host, String(port)]);
process.stdout.write(r.stdout);
process.stderr.write(r.stderr);

if (r.status !== 0) {
    ui.fatal(`interop failed (exit ${r.status})`);
}
ui.log("interop ok");
