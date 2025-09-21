module.exports = {
  root: true,
  env: {
    node: true,
    es2021: true,
  },
  parserOptions: {
    ecmaVersion: 2021,
    sourceType: 'script',
  },
  extends: ['eslint:recommended'],
  ignorePatterns: [
    'node_modules/',
    'client/',
    'server/dist/',
    'server/logs/**',
    'server/data/**',
    'server/temp/**',
  ],
  rules: {
    'no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    'no-constant-condition': ['warn', { checkLoops: false }],
    'no-console': 'off',
    'no-empty': ['error', { allowEmptyCatch: true }],
  },
}
