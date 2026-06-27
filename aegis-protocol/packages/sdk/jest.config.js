module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  moduleNameMapper: {
    '@aegis-protocol/spec': '<rootDir>/../spec/src/index.ts',
  },
  testTimeout: 10000,
};
