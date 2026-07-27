// Secure filesystem access for the exec approval policy store.
import fs from "node:fs";
import path from "node:path";
import { sha256Hex } from "./crypto-digest.js";
import {
  normalizeExecApprovalsInternal,
  parsePersistedExecApprovals,
} from "./exec-approvals-config.js";
import type { ExecApprovalsFile, ExecApprovalsSnapshot } from "./exec-approvals-core.js";
import { assertNoSymlinkParentsSync } from "./fs-safe-advanced.js";
import { resolveRequiredHomeDir } from "./home-dir.js";
import { replaceFileAtomicSync } from "./replace-file.js";

const MAX_EXEC_APPROVALS_RESTORE_BYTES = 16 * 1024 * 1024;

function hashExecApprovalsRaw(raw: string | null): string {
  // Preserve existing hashes for present files so mixed-version native/CLI
  // clients can still compare snapshots; only missing needs its own domain.
  return raw === null ? `missing:${sha256Hex("")}` : sha256Hex(raw);
}

export function hashExecApprovalsFile(file: ExecApprovalsFile): string {
  return hashExecApprovalsRaw(`${JSON.stringify(file, null, 2)}\n`);
}

export function isExecApprovalsTargetMissing(filePath: string): boolean {
  try {
    fs.lstatSync(filePath);
    return false;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return true;
    }
    throw err;
  }
}

export function isExecApprovalsLockMissing(filePath: string): boolean {
  try {
    const dir = fs.realpathSync(path.dirname(filePath));
    return isExecApprovalsTargetMissing(`${path.join(dir, path.basename(filePath))}.lock`);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return true;
    }
    throw err;
  }
}

function ensureDir(filePath: string) {
  const dir = path.dirname(filePath);
  assertNoExecApprovalsSymlinkParents(dir, resolveRequiredHomeDir());
  fs.mkdirSync(dir, { recursive: true });
  const dirStat = fs.lstatSync(dir);
  if (!dirStat.isDirectory() || dirStat.isSymbolicLink()) {
    throw new Error(`Refusing to use unsafe exec approvals directory: ${dir}`);
  }
  try {
    fs.chmodSync(dir, 0o700);
  } catch (err) {
    if (process.platform !== "win32") {
      throw err;
    }
  }
  return dir;
}

export function resolveCanonicalExecApprovalsTarget(filePath: string): string {
  const dir = ensureDir(filePath);
  return path.join(fs.realpathSync(dir), path.basename(filePath));
}

function assertNoExecApprovalsSymlinkParents(targetPath: string, trustedRoot: string): void {
  try {
    assertNoSymlinkParentsSync({
      rootDir: trustedRoot,
      targetPath,
      allowOutsideRoot: true,
      messagePrefix: "Refusing to traverse symlink in exec approvals path",
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new UnsafeExecApprovalsPathError(message, { cause: err });
  }
}

export class UnsafeExecApprovalsPathError extends Error {}

function assertSafeExecApprovalsStat(filePath: string, stat: fs.Stats): void {
  if (stat.isSymbolicLink()) {
    throw new UnsafeExecApprovalsPathError(
      `Refusing to write exec approvals via symlink: ${filePath}`,
    );
  }
  if (!stat.isFile()) {
    throw new UnsafeExecApprovalsPathError(
      `Refusing to use non-file exec approvals path: ${filePath}`,
    );
  }
}

function assertSafeExecApprovalsDestination(filePath: string): void {
  try {
    assertSafeExecApprovalsStat(filePath, fs.lstatSync(filePath));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      throw err;
    }
  }
}

function sameFilesystemEntry(left: fs.Stats, right: fs.Stats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

type ExecApprovalsRawState = { exists: false; raw: null } | { exists: true; raw: string };

function readExecApprovalsRawState(filePath: string): ExecApprovalsRawState {
  assertNoExecApprovalsSymlinkParents(path.dirname(filePath), resolveRequiredHomeDir());
  // Anchor policy bytes to one inode; otherwise a path swap can make the CAS
  // hash describe a different file than the guarded approvals destination.
  let before: fs.Stats;
  try {
    before = fs.lstatSync(filePath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return { exists: false, raw: null };
    }
    throw err;
  }
  assertSafeExecApprovalsStat(filePath, before);

  const noFollowFlag = fs.constants.O_NOFOLLOW ?? 0;
  let fd: number;
  try {
    fd = fs.openSync(filePath, fs.constants.O_RDONLY | noFollowFlag);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      throw new UnsafeExecApprovalsPathError(
        `Refusing to read changed exec approvals path: ${filePath}`,
        { cause: err },
      );
    }
    if (code === "ELOOP") {
      throw new UnsafeExecApprovalsPathError(
        `Refusing to write exec approvals via symlink: ${filePath}`,
        { cause: err },
      );
    }
    throw err;
  }
  try {
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || !sameFilesystemEntry(before, opened)) {
      throw new UnsafeExecApprovalsPathError(
        `Refusing to read changed exec approvals path: ${filePath}`,
      );
    }
    const raw = fs.readFileSync(fd, "utf8");
    let after: fs.Stats;
    try {
      after = fs.lstatSync(filePath);
    } catch (err) {
      throw new UnsafeExecApprovalsPathError(
        `Refusing to read changed exec approvals path: ${filePath}`,
        { cause: err },
      );
    }
    assertSafeExecApprovalsStat(filePath, after);
    if (!sameFilesystemEntry(opened, after)) {
      throw new UnsafeExecApprovalsPathError(
        `Refusing to read changed exec approvals path: ${filePath}`,
      );
    }
    return { exists: true, raw };
  } finally {
    fs.closeSync(fd);
  }
}

export function readExecApprovalsSnapshotFromPath(filePath: string): ExecApprovalsSnapshot {
  const state = readExecApprovalsRawState(filePath);
  if (!state.exists) {
    return {
      path: filePath,
      exists: false,
      raw: null,
      file: normalizeExecApprovalsInternal({ version: 1, agents: {} }),
      hash: hashExecApprovalsRaw(null),
    };
  }
  return {
    path: filePath,
    exists: true,
    raw: state.raw,
    file: parsePersistedExecApprovals(state.raw),
    hash: hashExecApprovalsRaw(state.raw),
  };
}

// Coerce legacy/corrupted allowlists into `ExecAllowlistEntry[]` before we spread
// entries to add ids (spreading strings creates {"0":"l","1":"s",...}).
export function hardenUnchangedExecApprovals(filePath: string): boolean {
  ensureDir(filePath);
  assertSafeExecApprovalsDestination(filePath);
  let stat: fs.Stats;
  try {
    stat = fs.statSync(filePath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return false;
    }
    throw err;
  }
  if (stat.nlink > 1) {
    return false;
  }
  try {
    fs.chmodSync(filePath, 0o600);
  } catch {
    // best-effort on platforms without chmod
  }
  return true;
}

export function writeExecApprovalsRaw(filePath: string, raw: string) {
  ensureDir(filePath);
  assertNoExecApprovalsSymlinkParents(path.dirname(filePath), resolveRequiredHomeDir());
  assertSafeExecApprovalsDestination(filePath);
  const fileSystem = {
    ...fs,
    writeFileSync: ((target, data, options) => {
      fs.writeFileSync(target, data, options);
      if (typeof target !== "number") {
        try {
          fs.chmodSync(target, 0o600);
        } catch {
          // Best-effort on platforms that do not enforce POSIX modes.
        }
      }
    }) as typeof fs.writeFileSync,
  };
  replaceFileAtomicSync({
    filePath,
    content: raw,
    dirMode: 0o700,
    mode: 0o600,
    tempPrefix: ".exec-approvals",
    syncTempFile: true,
    copyFallbackOnPermissionError: true,
    copyFallbackRestore: "restore-original",
    maxRestoreBytes: MAX_EXEC_APPROVALS_RESTORE_BYTES,
    destinationHardlinks: "reject",
    fileSystem,
    beforeRename: ({ filePath: destinationPath, tempPath }) => {
      assertNoExecApprovalsSymlinkParents(path.dirname(destinationPath), resolveRequiredHomeDir());
      assertSafeExecApprovalsDestination(destinationPath);
      assertSafeExecApprovalsStat(tempPath, fs.lstatSync(tempPath));
    },
  });
}
