function validateDomain(domain) {
  if (!/^(?:[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)*[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?::\d+)?$/.test(
    domain
  )) {
    throw new Error(
      "The provided domain is invalid. Ensure that the domain adheres to RFC 1035"
    );
  }
}

export { validateDomain };
//# sourceMappingURL=utils.js.map
