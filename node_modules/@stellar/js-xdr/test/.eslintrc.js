module.exports = {
  env: {
    mocha: true,
    es2022: true
  },
  parserOptions: { ecmaVersion: 2022, sourceType: 'module' },
  globals: {
    XDR: true,
    chai: true,
    sinon: true,
    expect: true,
    stub: true,
    spy: true
  },
  rules: {
    'no-unused-vars': 0,
    'node/no-unsupported-features/es-syntax': 0
  }
};
