// Finite test double for Node (which has no DOMParser). Trees were parsed with
// stdlib XML from the shared raw fixtures. Actual XML parsing/security is also
// exercised by the Chromium chain test using these exact raw XML documents.
import {readFileSync} from 'node:fs';
const cases = JSON.parse(readFileSync(new URL('../../../tests/fixtures/visual-assets-svg-v1.json', import.meta.url))).cases;
function element(tree) {
    const children = tree.children.map(element);
    return {...tree, querySelectorAll: () => children.flatMap(child => [child, ...child.querySelectorAll('*')])};
}
export class SvgFixtureParser {
    parseFromString(text) {
        const tree = cases.find(fixture => fixture.xml === text)?.parsed_document;
        return tree ? {documentElement: element(tree), getElementsByTagName: () => []} : {documentElement: null, getElementsByTagName: () => [{}]};
    }
}
export {cases as svgFixtures};
