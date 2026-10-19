// scripts/lib/args.mjs
//
// Command-line surface for the ngtcp2 fork's build.
//
// Deliberately NOT the upstream CMake surface. The fork exists to carry one
// extra crypto backend, and a second build system in a tree that already has
// one is a second thing to keep working. Everything here is one `node
// scripts/build.mjs`.

export function parseArgs(argv) {
    const has = (f) => argv.includes(f);

    const asan = has("--asan");
    const tsan = has("--tsan");
    if (asan && tsan) {
        console.error("error: --asan and --tsan are mutually exclusive");
        process.exit(1);
    }

    const release = has("--release");

    /* Object paths are keyed by config so a sanitizer build and a plain one
     * never share artifacts. Same reasoning as cvmsockets/cvmcrypt. */
    const variant = asan ? "-asan" : tsan ? "-tsan" : "";

    return {
        release,
        sanitizer: asan ? "asan" : tsan ? "tsan" : null,
        config: (release ? "release" : "debug") + variant,
        asan,
        tsan,
        lib: has("--lib") || has("--all"),
        tests: has("--tests") || has("--all"),
        crypto: has("--crypto") || has("--all"),
        all: has("--all"),
        clean: has("--clean"),
        verbose: has("-v") || has("--verbose"),
    };
}

export const help = {
    usage: "node scripts/build.mjs [options]",
    options: [
        "--all              lib + crypto + tests",
        "--lib              libngtcp2.a only",
        "--crypto           crypto/cvmcrypt only",
        "--tests            the upstream unit test binary",
        "--release          optimize (-O2 -DNDEBUG); default is debug",
        "--asan             build with AddressSanitizer",
        "--tsan             build with ThreadSanitizer",
        "--clean            remove build/ and exit",
        "-v, --verbose      echo every compiler invocation",
    ],
};
