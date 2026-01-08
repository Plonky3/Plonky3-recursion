# RFC 0000: RFC Template

> This file is an RFC template.
> Copy it to a new file named: `docs/rfcs/NNNN-<kebab-case-title>.md`
>
> Example: `docs/rfcs/0007-lookups.md`
>
> Then open a PR with the new RFC. The PR is the review thread.
> Once accepted, update `Status:` to `Accepted` and land the PR.
>
> **When do we require an RFC?**
> If an issue is labeled `needs-rfc` (large change), you must write an RFC
> (or a design-only PR with a similar structure) before heavy implementation.

---

- **Author(s):** @your-handle
- **DRI:** @assignee-handle
- **Status:** Draft | In Review | Accepted | Implemented | Rejected
- **Created:** YYYY-MM-DD
- **Tracking issue:** #<id>

## 1. Summary
What this changes and why.

## 2. Motivation / Problem statement
What problem are we solving? Include concrete pain points and what “better” looks like.

## 3. Goals and non-goals
**Goals**
- ...

**Non-goals**
- ...

## 4. Proposed design
### 4.1 High-level approach
Describe the approach and key invariants.

### 4.2 APIs / traits / types
Show intended public surface.

```rust
// Rust signatures / structs / traits (sketches are fine)
```