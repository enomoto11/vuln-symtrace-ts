// Uses lodash's `template`, the export GHSA-r5fr names as code-injection
// prone. Because a used export overlaps an advisory's mentioned API, that
// vulnerability should be reported with a [review priority] hint.
import { template } from 'lodash';

export function render(source: string): (data: object) => string {
  return template(source);
}
