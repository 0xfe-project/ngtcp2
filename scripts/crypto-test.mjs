// scripts/crypto-test.mjs
//
// Build and run the cvmcrypt backend's known-answer tests.
//
// This target is separate from the upstream suite on purpose: the upstream
// tests test lib/ and nothing else, and linking the backend into them would
// drag the whole of cvmcrypt into a binary that has no business carrying it.
//
// What gets linked:
//
//   crypto/cvmcrypt/cvmcrypt_test.c   munit cases, this repository
//   crypto/cvmcrypt/cvmcrypt.c        the backend, this repository
//   crypto/shared.c                   backend-independent helpers, upstream
//   build/lib/<config>/libngtcp2.a    the transport, upstream
//   tests/munit/munit.c               the test framework
//   $CVMCRYPT_DIR/src/**/*.c          the crypto library, external checkout
//   $CVMCRYPT_DIR/tests/support/rt_stub.c   rt_mem_* over libc, hosted only
//
// cvmcrypt is compiled here with the same freestanding flags its own build
// uses, because that is how it is designed to be compiled; the test binary
// itself is hosted so munit and libc are available.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { logger, mkdirp, collect } from "./lib/util.mjs";
import { discover, freestandingInclude } from "./lib/toolchain.mjs";
import { runOrDie, run } from "./lib/exec.mjs";
import { ensureVersionHeader } from "./lib/version.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const BUILD = path.join(ROOT, "build");
const ui = logger("crypto-test");

const CVMCRYPT = path.resolve(process.env.CVMCRYPT_DIR || path.join(ROOT, "..", "cvmcrypt"));
if (!fs.existsSync(path.join(CVMCRYPT, "include", "cvmcrypt", "cvmcrypt.h"))) {
    ui.fatal(`cvmcrypt not found at ${CVMCRYPT} (set CVMCRYPT_DIR)`);
}

const config = process.env.CRYPTO_TEST_CONFIG || "debug";

function main() {
    const toolchain = discover();
    mkdirp(BUILD);
    ensureVersionHeader({ root: ROOT, buildDir: BUILD, ui });

    const gen = path.join(BUILD, "gen", "include");
    const munit = path.join(ROOT, "tests", "munit");

    const inc = [
        "-I", gen,
        "-I", path.join(ROOT, "lib", "includes"),
        "-I", path.join(ROOT, "lib"),
        "-I", path.join(ROOT, "crypto", "includes"),
        "-I", path.join(ROOT, "crypto"),
        "-I", munit,
        "-I", path.join(CVMCRYPT, "include"),
        "-I", path.join(CVMCRYPT, "src"),
        "-I", path.join(CVMCRYPT, "vendor", "cvm", "rt"),
    ];

    /* cvmcrypt's own objects: freestanding, as its build does. */
    const crySrcs = collect(path.join(CVMCRYPT, "src"), [".c", ".S"]);
    const cryObjs = [];
    const objDir = path.join(BUILD, "obj", config, "cvmcrypt-lib");
    for (const src of crySrcs) {
        const obj = path.join(objDir, path.relative(CVMCRYPT, src) + ".o");
        mkdirp(path.dirname(obj));
        runOrDie(
            toolchain.cc,
            [
                "-std=c11", "-w", "-g", "-O0",
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
    const bin = path.join(binDir, "cvmcrypt-test");

    const hosted = [
        path.join(ROOT, "crypto", "cvmcrypt", "cvmcrypt_test.c"),
        path.join(ROOT, "crypto", "cvmcrypt", "cvmcrypt.c"),
        path.join(ROOT, "crypto", "shared.c"),
        path.join(munit, "munit.c"),
        path.join(CVMCRYPT, "tests", "support", "rt_stub.c"),
    ];

    runOrDie(
        toolchain.cc,
        [
            "-std=c11", "-w", "-g", "-O0",
            ...inc,
            ...hosted,
            ...cryObjs,
            path.join(BUILD, "lib", "debug", "libngtcp2.a"),
            "-o", bin,
        ],
        { ui, what: "link cvmcrypt-test" },
    );

    ui.log(`built ${path.relative(ROOT, bin)}`);

    const r = run(bin, [], { verbose: true });
    process.stdout.write(r.stdout);
    process.stderr.write(r.stderr);
    if (r.status !== 0) {
        ui.fatal(`tests failed (exit ${r.status})`);
    }
}

main();
