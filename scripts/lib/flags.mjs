// scripts/lib/flags.mjs
//
// Compiler flag sets for the fork, split by who wrote the code.
//
//   upstream   lib/ and tests/ — third party. Compiled quiet, never -Werror.
//              Their warnings are not our build failures, and fixing them
//              would mean carrying a patch set against a tree we want to
//              rebase onto upstream every few months.
//
//   ours       crypto/cvmcrypt/ — our code, held to the cvm standard:
//              warnings are errors, pedantic, no implicit anything.
//
// The split is the whole point of having a flags module here.

import path from "node:path";

export const STD = "-std=c11";

export const DEBUG_FLAGS = ["-g", "-O0", "-fno-omit-frame-pointer"];
export const RELEASE_FLAGS = ["-O2", "-DNDEBUG"];

export const UPSTREAM_WARN = ["-w"];
export const OURS_WARN = ["-Wall", "-Wextra", "-Werror", "-Wpedantic", "-fno-common"];

export function sanitizerFlags({ asan, tsan }) {
    if (asan) return ["-fsanitize=address"];
    if (tsan) return ["-fsanitize=thread"];
    return [];
}

/**
 * Include paths.
 *
 *   build/gen/include   the generated ngtcp2/version.h
 *   lib/includes        the public header: <ngtcp2/ngtcp2.h>
 *   lib                 internal headers (ngtcp2_conn.h and friends)
 *   tests/munit         munit.h, tests only
 */
export function includeFlags({ root, buildDir, tests = false, ours = false }) {
    const dirs = [
        path.join(buildDir, "gen", "include"),
        path.join(root, "lib", "includes"),
        path.join(root, "lib"),
    ];
    if (tests) dirs.push(path.join(root, "tests", "munit"));
    if (ours) {
        /*
         * cvmcrypt is an external dependency, not vendored: the fork links
         * against whatever checkout the caller points at. CVMCRYPT_DIR makes
         * "the sibling checkout" the default without hard-coding a path in
         * the build.
         */
        const cvmcrypt = path.resolve(process.env.CVMCRYPT_DIR || path.join(root, "..", "cvmcrypt"));
        dirs.push(path.join(cvmcrypt, "include"), path.join(cvmcrypt, "src"));
        /* The crypto API header lives under crypto/, not lib/. */
        dirs.push(path.join(root, "crypto", "includes"), path.join(root, "crypto"));
        /* cvm's rt/ supplies base/types.h and the rt_* ABI. */
        dirs.push(path.join(cvmcrypt, "vendor", "cvm", "rt"));
    }
    return dirs.flatMap((d) => ["-I", d]);
}

export function flagsFor({ tier, opts, root, buildDir, tests = false, extra = [] }) {
    const ours = tier === "ours";
    return [
        STD,
        ...(tier === "ours" ? OURS_WARN : UPSTREAM_WARN),
        "-DNGTCP2_STATICLIB",
        ...(opts.release ? RELEASE_FLAGS : DEBUG_FLAGS),
        ...sanitizerFlags(opts),
        ...includeFlags({ root, buildDir, tests, ours }),
        ...extra,
    ];
}
