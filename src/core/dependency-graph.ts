/**
 * A resolved dependency graph: each `name@version` key maps to the
 * `name@version` keys of its own resolved dependencies (forward edges).
 */
export type DependencyGraph = ReadonlyMap<string, readonly string[]>;

/**
 * A chain of `name@version` keys from a direct dependency (first element)
 * down to a transitive package (last element).
 */
export type DependencyPath = readonly string[];

/**
 * Finds how a transitive package is pulled into the dependency tree.
 *
 * Returns one shortest chain from each direct dependency that — directly or
 * indirectly — depends on `target`. Returns an empty array when no direct
 * dependency reaches the target, which includes the case of an empty graph
 * (lockfile formats whose graph is not yet extracted).
 */
export function findDependencyPaths(
  graph: DependencyGraph,
  directKeys: ReadonlySet<string>,
  target: string,
): DependencyPath[] {
  // Reverse adjacency: child -> the parents that depend on it.
  const parents = new Map<string, string[]>();
  for (const [node, children] of graph) {
    for (const child of children) {
      let list = parents.get(child);
      if (list === undefined) {
        list = [];
        parents.set(child, list);
      }
      list.push(node);
    }
  }

  // Breadth-first walk upward from `target`. `cameFrom` records, for each
  // visited node, the child it was reached through — one step toward target.
  const cameFrom = new Map<string, string>();
  const visited = new Set<string>([target]);
  const queue: string[] = [target];
  const paths: DependencyPath[] = [];

  for (let head = 0; head < queue.length; head++) {
    const node = queue[head];
    if (node === undefined) continue;

    if (node !== target && directKeys.has(node)) {
      // A direct dependency is a root: record the chain and stop climbing,
      // since nothing above a declared dependency is more relevant.
      paths.push(reconstructPath(node, target, cameFrom));
      continue;
    }

    for (const parent of parents.get(node) ?? []) {
      if (!visited.has(parent)) {
        visited.add(parent);
        cameFrom.set(parent, node);
        queue.push(parent);
      }
    }
  }

  return paths;
}

/** Rebuilds the root -> target chain by following `cameFrom` pointers. */
function reconstructPath(
  root: string,
  target: string,
  cameFrom: ReadonlyMap<string, string>,
): string[] {
  const path: string[] = [root];
  let current = root;
  while (current !== target) {
    const next = cameFrom.get(current);
    if (next === undefined) break;
    path.push(next);
    current = next;
  }
  return path;
}
