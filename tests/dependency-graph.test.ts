import { describe, it, expect } from 'vitest';
import { findDependencyPaths, type DependencyGraph } from '../src/core/dependency-graph.js';

function graphOf(edges: Record<string, string[]>): DependencyGraph {
  return new Map(Object.entries(edges));
}

describe('findDependencyPaths', () => {
  it('traces a linear chain from a direct dependency to a transitive package', () => {
    const graph = graphOf({
      'a@1.0.0': ['b@1.0.0'],
      'b@1.0.0': ['c@1.0.0'],
      'c@1.0.0': [],
    });
    const paths = findDependencyPaths(graph, new Set(['a@1.0.0']), 'c@1.0.0');
    expect(paths).toEqual([['a@1.0.0', 'b@1.0.0', 'c@1.0.0']]);
  });

  it('reports one chain per direct dependency that pulls the package in', () => {
    const graph = graphOf({
      'a@1.0.0': ['x@1.0.0'],
      'b@1.0.0': ['x@1.0.0'],
      'x@1.0.0': [],
    });
    const paths = findDependencyPaths(graph, new Set(['a@1.0.0', 'b@1.0.0']), 'x@1.0.0');
    expect(paths).toHaveLength(2);
    expect(paths).toContainEqual(['a@1.0.0', 'x@1.0.0']);
    expect(paths).toContainEqual(['b@1.0.0', 'x@1.0.0']);
  });

  it('returns an empty array when no direct dependency reaches the target', () => {
    const graph = graphOf({
      'a@1.0.0': ['b@1.0.0'],
      'b@1.0.0': [],
      'orphan@1.0.0': ['c@1.0.0'],
    });
    expect(findDependencyPaths(graph, new Set(['a@1.0.0']), 'c@1.0.0')).toEqual([]);
  });

  it('returns an empty array for an empty graph', () => {
    expect(findDependencyPaths(new Map(), new Set(['a@1.0.0']), 'c@1.0.0')).toEqual([]);
  });

  it('terminates on a cyclic graph', () => {
    const graph = graphOf({
      'a@1.0.0': ['b@1.0.0'],
      'b@1.0.0': ['a@1.0.0', 'c@1.0.0'],
      'c@1.0.0': [],
    });
    const paths = findDependencyPaths(graph, new Set(['a@1.0.0']), 'c@1.0.0');
    expect(paths).toEqual([['a@1.0.0', 'b@1.0.0', 'c@1.0.0']]);
  });

  it('stops at the nearest direct dependency rather than climbing past it', () => {
    // a -> b -> target, and both a and b are direct dependencies.
    const graph = graphOf({
      'a@1.0.0': ['b@1.0.0'],
      'b@1.0.0': ['t@1.0.0'],
      't@1.0.0': [],
    });
    const paths = findDependencyPaths(graph, new Set(['a@1.0.0', 'b@1.0.0']), 't@1.0.0');
    expect(paths).toEqual([['b@1.0.0', 't@1.0.0']]);
  });
});
