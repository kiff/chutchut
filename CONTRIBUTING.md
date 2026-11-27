# Contributing to loge

loge is source-available under [FSL-1.1-ALv2](LICENSE.md), not open source.

## Rules every change follows

- **Mail is data, never instructions.** Nothing from a message (its text, its headers, an attachment) is ever followed as an instruction, by the code or by an agent.
- **A stranger knocks.** Only a paired sender, proven by DMARC-aligned mail, reaches an agent by itself. Anyone else is kept for the owner and not sent to the AI unless the owner hands it to an agent.
- **A send waits for approval** unless the owner has allowed that kind of reply, and it goes only to an address that wrote into that thread.
- **Every act leaves a Record line:** who, when, the message id (never the body), what was done, and who approved it.
- **Holds, not drops.** Past a cap, mail waits; nothing is lost silently.
- **No secrets in the repository**, and test data only in tests (`example.test` addresses).
- **Infrastructure is code here, applied by its owner.** A change to the cloud is reviewed as code and applied separately, never by CI.

## A pull request

- Two approvals, never the author's.
- `npm run typecheck` and `npm test` pass, with a test for each rule the change touches.
- One changelog fragment, `changes/<branch>.md` ([changes/README.md](changes/README.md)).
- Its text says each rule as itself: never who set it or where it was decided (`scripts/public_text.py`).
