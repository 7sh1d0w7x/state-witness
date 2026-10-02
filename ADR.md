# ADR — Architecture Decision Records (state-witness)

> [!info] Ce e
> Fișierul unde documentezi **deciziile TALE** (arhitectură, logică, trade-off-uri).
> **Scop dublu:** (1) îți amintești de ce ai ales ceva; (2) **= dovada de „human authorship" pe care o cer granturile** (NLnet: „human contributors expected to understand and explain design and code decisions").

> [!important] Cum se folosește
> Completezi **10 linii** per decizie. Nu scrii de la zero — copiezi template-ul.
> Format: dată + decizie + context + alternative + consecințe.

---

## Template (copiază-l)

```markdown
## ADR-XXX: [Titlu scurt]

**Data:** 2026-XX-XX
**Status:** propus / acceptat / înlocuit

### Context
Ce problemă era de rezolvat? Ce constrângeri existau?

### Decizie
Ce am ales? (o propoziție clară)

### Alternative considerate
- A: ... (de ce nu)
- B: ... (de ce nu)

### Consecințe
- ✅ pozitiv
- ⚠️ negativ / cost

### Verificare
Cum știu că e corect? (test, RFC, sursă)
```

---

## Decizii (completează)

## ADR-001: Folosirea `sshd -T` pentru starea efectivă SSH

**Data:** 2026-09-30
**Status:** acceptat

### Context
`state-witness` trebuie să raporteze **starea efectivă** a SSH, nu ce scrie în `sshd_config` (care poate fi suprascris de include-uri, defaults, sau opțiuni de linie de comandă).

### Decizie
Rulez `sshd -T` (dump-ul configurării efective) în loc să parsez `sshd_config`.

### Alternative considerate
- A: Parsare `sshd_config` direct → ❌ ratează include-uri + defaults + prioritate
- B: Citire `/proc` → ❌ nu expune config-ul SSH

### Consecințe
- ✅ Starea REALĂ, nu cea declarată
- ⚠️ Necesită root (host keys) → tool-ul cere `sudo`

### Verificare
Testat pe mașina proprie: `PermitRootLogin: prohibit-password` + `PasswordAuthentication: yes` (Warn corect).

---

## ADR-002: [următoarea decizie]

**Data:**
**Status:**

### Context

### Decizie

### Alternative considerate

### Consecințe

### Verificare

---
*ADR-uri state-witness · început 2 oct 2026*
