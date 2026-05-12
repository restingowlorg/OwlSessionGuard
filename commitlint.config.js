module.exports = {
  extends: ["@commitlint/config-conventional"],
  rules: {
    "type-enum": [
      2,
      "always",
      ["feat", "fix", "docs", "style", "refactor", "perf", "test", "chore", "ci", "build", "revert"]
    ],
    "scope-enum": [
      2,
      "always",
      ["storage", "api", "db", "ci", "core", "infra", "config", "test", "common", "docs"]
    ],
    "header-min-length": [2, "always", 10],
    "header-max-length": [2, "always", 100],
    "subject-empty": [2, "never"],
    "subject-full-stop": [2, "never", "."],
    "subject-case": [2, "never", ["sentence-case", "start-case", "pascal-case", "upper-case"]]
  }
};
