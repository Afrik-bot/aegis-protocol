module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  moduleNameMapper: {
    '@aegis-protocol/spec': '<rootDir>/../spec/dist/index.js',
  },
  testTimeout: 10000,
};