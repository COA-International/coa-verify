# Security policy

`coa-verify` decides whether a certificate is reported as signed by a key you trust, so we treat any
way to make it report something untrue as a security issue. That includes a forged or altered record
or file being accepted, trust being granted to a key you did not pin, a record of one program operator
being trusted under another's key, an anchor being reported as attested when it is not, fetching
anything other than the `--online` server you named, or terminal output that a crafted record can
disguise.

Please report it privately through GitHub: **Security, then "Report a vulnerability"** in this
repository. Do not open a public issue. Include the input that shows the problem (a test vector is
ideal) and the version (`coa-verify --version`).

We aim to acknowledge reports within three working days. Fixes are released as a new version with
the advisory published once users can upgrade.

Only the latest release is supported.
