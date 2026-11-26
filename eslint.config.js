// ESLint flat config for the vanilla-JS WebView UI (no bundler: every file is a classic browser script).
const js = require("@eslint/js");
const globals = require("globals");

module.exports = [
  {
    ignores: ["ui/vendor/**", "ui/data/ne*.js", "**/*.min.js", "node_modules/**", "target/**", "qa/out/**"],
  },
  js.configs.recommended,
  {
    files: ["ui/**/*.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "script",
      globals: {
        ...globals.browser,
        FOCA: "readonly", // UI namespace (window.FOCA), created by js/core.js
        FocaNative: "readonly", // Android JavascriptInterface injected by MainActivity
      },
    },
    rules: {
      // Catch blocks and callbacks often ignore their argument on purpose.
      "no-unused-vars": ["error", { args: "none", caughtErrors: "none", ignoreRestSiblings: true }],
      // UI strings intentionally contain non-breaking spaces.
      "no-irregular-whitespace": ["error", { skipStrings: true, skipTemplates: true }],
      "no-empty": ["error", { allowEmptyCatch: true }],
    },
  },
  {
    files: ["eslint.config.js"],
    languageOptions: { sourceType: "commonjs", globals: { ...globals.node } },
  },
];
