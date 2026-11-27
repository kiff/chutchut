# Unreleased changes, one file per pull request

A pull request puts its changelog entry here, as `changes/<branch>.md`: its branch's name, with each `/` as `-`. It never edits [CHANGELOG.md](../CHANGELOG.md), so two pull requests never conflict on the same line.

- **The entry** is one bullet, written as CHANGELOG.md's are: what changed for the person.
- **Nothing user-visible** (a refactor, a doc fix): add the file empty.
- **The check** (`scripts/changelog.py check`) fails a pull request that edits CHANGELOG.md, adds no fragment or more than one, names it for another branch, or changes another pull request's fragment.
- **At a release**, `scripts/changelog.py fold` moves every fragment into CHANGELOG.md.
