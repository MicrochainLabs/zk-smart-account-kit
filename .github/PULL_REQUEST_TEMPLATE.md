## Description

<!-- Briefly describe what this PR does and why. Link the related issue if applicable. -->

Closes #

## Type of Change

- [ ] Bug fix
- [ ] New feature / verifier adapter
- [ ] Circuit change (Noir `.nr` files modified)
- [ ] Refactor / code cleanup
- [ ] Documentation
- [ ] Dependency update
- [ ] Other: ___

## Checklist

### General

- [ ] I have read [CONTRIBUTING.md](CONTRIBUTING.md)
- [ ] My branch is up to date with `develop` (PRs should target `develop`, not `main`)
- [ ] My changes do not introduce new linting or compiler warnings

### Solidity

- [ ] Solidity compiles (`forge build` / `npx hardhat compile`)
- [ ] Tests pass, where a suite exists (`npx hardhat test`, `forge test`)
- [ ] New functionality has corresponding test coverage

### Noir Circuits (if `.nr` files were modified)

- [ ] Circuits compile without errors (`nargo compile --workspace`)
- [ ] Circuit tests pass (`nargo test --workspace`)
- [ ] Solidity verifiers still generate from the circuits (`bb write_vk` + `bb write_solidity_verifier`; CI also checks this)
- [ ] Breaking changes to public inputs are documented and discussed in a linked issue

### Documentation

- [ ] README updated (if user-facing behaviour changed)
- [ ] Inline comments added for non-obvious logic

## Testing Notes

<!-- Describe how you tested these changes. Include relevant commands, test names, or screenshots. -->

## Additional Notes

<!-- Anything else reviewers should know. -->
