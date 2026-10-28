# Project Development Rules

## General
- Read the existing implementation before changing it.
- Do not rewrite working code without a clear reason.
- Prefer small, focused changes.
- Avoid unrelated refactoring.

## Implementation
- Read the relevant implementation plan stated in the docs/implementation/features  dir before starting to work.
- Follow the dependency order between plans.as stated inside the overview.md file
- Never silently skip a requirement.
- Update the relevant plan when a task is completed.

## Testing
- Write tests for new functionality.
- Run relevant tests after each milestone.
- Run the complete test suite before declaring completion.
- Never claim a test passed without actually running it.
- Investigate failures instead of hiding or bypassing them.

## Safety
- Never expose secrets or credentials.
- Never delete user data without authorization.
- Never make destructive database changes without approval.
- Preserve unrelated modifications in the working tree.

## Completion
- Report implemented features.
- Report tests actually executed and their results.
- List unfinished tasks and known limitations.
- Review the final changes for regressions.
  
  Before declaring the project complete:

1. Inspect the repository's final changes.
2. Run the relevant automated tests.
3. Run the project's available linting and type checks.
4. Verify the acceptance criteria for each implementation plan.
5. Check for missing functionality and regressions.
6. Identify any tasks that could not be completed.
