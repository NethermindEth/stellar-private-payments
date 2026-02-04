module.exports = {
  testEnvironment: 'node',
  transform: {
    '^.+\\.js$': 'babel-jest',
  },
  clearMocks: true,
  moduleNameMapper: {
    '^\\./prover\\.js$': '<rootDir>/js/__mocks__/prover.js',
    '^\\./prover-client\\.js$': '<rootDir>/js/__mocks__/prover-client.js',
  },
};
