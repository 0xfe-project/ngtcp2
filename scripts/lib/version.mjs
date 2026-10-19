// scripts/lib/version.mjs
//
// Generate ngtcp2/version.h from version.h.in, exactly as CMake would, from
// the single source of truth: the `project(... VERSION ...)` line.

import fs from "node:fs";
import path from "node:path";
import { mkdirp } from "./util.mjs";

export function ensureVersionHeader({ root, buildDir, ui }) {
    const cmake = fs.readFileSync(path.join(root, "CMakeLists.txt"), "utf8");
    const m = cmake.match(/project\(\s*ngtcp2\s+VERSION\s+([0-9]+)\.([0-9]+)\.([0-9]+)/);
    if (!m) {
        ui.fatal("cannot read the version from CMakeLists.txt");
    }

    const [major, minor, patch] = [Number(m[1]), Number(m[2]), Number(m[3])];
    const version = `${major}.${minor}.${patch}`;
    const num = (major << 16) | (minor << 8) | patch;
    const versionNum = "0x" + num.toString(16).toUpperCase().padStart(6, "0");

    const tpl = fs.readFileSync(
        path.join(root, "lib", "includes", "ngtcp2", "version.h.in"),
        "utf8",
    );
    const body = tpl
        .replaceAll("@PACKAGE_VERSION@", version)
        .replaceAll("@PACKAGE_VERSION_NUM@", versionNum);

    const outDir = path.join(buildDir, "gen", "include", "ngtcp2");
    const out = path.join(outDir, "version.h");
    mkdirp(outDir);

    const prev = fs.existsSync(out) ? fs.readFileSync(out, "utf8") : null;
    if (prev !== body) fs.writeFileSync(out, body);

    return { version, versionNum };
}
