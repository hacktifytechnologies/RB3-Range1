# solve_blue.md — M5 · ext-contractor-portal
## Blue Team Detection, Containment & Remediation

## 1. Detection
```
journalctl -u rpal-contractor-portal | grep "GET /.git"
```
Suricata: `alert http any -> any 4000 (content:"GET /.git/"; http_uri; sid:9001501;)`

## 2. Containment
Change `dotfiles: 'allow'` to `dotfiles: 'ignore'`. Rotate admin token immediately.

## 3. Remediation
1. `express.static()` must never use `dotfiles: 'allow'`
2. Deploy via git archive or CI/CD — never deploy the working checkout directory
3. Treat any credential that appeared in git history as permanently compromised
4. Use `git-secrets` pre-commit hook to prevent secret commits
