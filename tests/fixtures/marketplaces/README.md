# Marketplace contract fixtures

These files are sanitized, reviewable protocol subsets. They are evidence for
Drey's compile-time marketplace policy; they are not live-interoperability proof
and cannot activate a signing template.

`manifest.json` pins source, access date, upstream label, transformation, and
the SHA-256 of every canonical subset. `pnpm fixtures:marketplaces:check` is
offline. Refresh writes only digest candidates for human review and never
updates the registry or an existing fixture automatically.

The only wallet material permitted in generated PSBT fixtures is the repository's
public signet mnemonic or a newly generated disposable signet wallet. Never add
credentials, mainnet seeds, browser profiles, or production API responses.
