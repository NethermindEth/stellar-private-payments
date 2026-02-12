module.exports = {
  testEnvironment: "node",
  transform: {
    "^.+\\.js$": "babel-jest",
  },
  clearMocks: true,
  testPathIgnorePatterns: ["/node_modules/", "<rootDir>/e2e/"],
  moduleNameMapper: {
    "^\\./prover\\.js$": "<rootDir>/js/__mocks__/prover.js",
    "^\\./prover-client\\.js$": "<rootDir>/js/__mocks__/prover-client.js",
  },
};
