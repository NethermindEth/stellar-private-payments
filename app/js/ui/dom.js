// Element builders shared by both pages.
const SVG_NS = 'http://www.w3.org/2000/svg';

export function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
}

// Drops anything that is not a Node, so callers can list optional children inline.
export function elc(tag, className, children) {
    const node = el(tag, className);
    node.append(...children.filter((child) => child instanceof Node));
    return node;
}

export function svgEl(tag, attrs, children = []) {
    const node = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    node.append(...children);
    return node;
}
