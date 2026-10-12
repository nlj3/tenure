The integration harness for this folder is planned and not yet written, so there are no tests here yet.
When it exists, it will create a throwaway user in a tenant the maintainer owns, run onboard, role change and offboard with the device steps off, verify the audit chain, and then delete the user.
Run it with ./build.ps1 -Task Integration. The task refuses to start unless the environment variable TENURE_INTEGRATION is set to 1.
TENURE_INTEGRATION=1 is the only environment variable build.ps1 reads.
Use only a tenant the maintainer owns.
Nothing in this folder runs in CI. The CI workflow runs the CI task, which does not include Integration.
