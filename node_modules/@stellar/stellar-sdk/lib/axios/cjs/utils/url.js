'use strict';

function stringifyTemplateValue(value) {
  return Array.isArray(value) ? value.join(",") : value.toString();
}
function expandUriTemplate(template, variables, baseUrl) {
  const queryNames = [];
  const withoutQueryTemplate = template.replace(
    /\{\?([^}]+)\}/g,
    (_match, names) => {
      queryNames.push(...names.split(","));
      return "";
    }
  );
  const expanded = withoutQueryTemplate.replace(
    /\{([^?][^}]*)\}/g,
    (_match, name) => {
      const value = variables[name];
      return typeof value === "undefined" ? "" : encodeURIComponent(stringifyTemplateValue(value));
    }
  );
  const url = new URL(expanded, baseUrl);
  queryNames.forEach((name) => {
    const value = variables[name];
    if (typeof value !== "undefined") {
      url.searchParams.set(name, stringifyTemplateValue(value));
    }
  });
  return url.toString();
}

exports.expandUriTemplate = expandUriTemplate;
//# sourceMappingURL=url.js.map
