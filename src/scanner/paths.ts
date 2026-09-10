/**
 * Path normalization for scan output.
 *
 * Policy: every path stored on a ConfigFile (`path`), on a DanglingSymlink
 * (`path`), or compared against a literal such as ".vscode/tasks.json" uses
 * forward slashes, regardless of host platform. Normalization happens at the
 * point the relative path is produced (right after `relative()`), so rules,
 * reporters, and tests can rely on a single separator. File system access
 * keeps using the native path returned by `join()`; Node's `path.resolve`
 * and `path.join` on Windows accept forward slashes when a consumer needs to
 * turn a stored path back into a native one.
 */
export function toPosixPath(filePath: string): string {
  return filePath.replace(/\\/g, "/");
}
