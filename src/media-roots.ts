import * as path from "node:path";

export function mergeYZJMediaLocalRoots(...rootLists: Array<readonly string[] | undefined>): string[] {
  const roots: string[] = [];
  const seen = new Set<string>();
  for (const rootList of rootLists) {
    for (const rawRoot of rootList ?? []) {
      const root = rawRoot.trim();
      if (!root) continue;
      const key = path.resolve(root).toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      roots.push(root);
    }
  }
  return roots;
}
