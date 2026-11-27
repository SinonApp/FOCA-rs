# Project risk score

The overview, the reports and the alerts show one risk score from 0 to 100 per project (or per
report selection). It is computed the same way in the core (`foca_analysis::findings::risk`), the
engine (`rules::risk_score`) and the UI (`FOCA_RULES.riskScore` in `ui/js/sel.js`).

## Counted findings

Every finding counts except false positives, fixed findings and findings tagged `out_of_scope`
(environment context, for example Shodan data of a host outside the scope). Info findings weigh 0.

## Formula

1. Weight by severity: critical 0.25, high 0.12, medium 0.05, low 0.02, info 0.
2. Within one category (documents, people, software, web, TLS, DNS, mail, cloud, hosts) the
   findings are taken strongest first, and the k-th non-critical finding counts `w / k`. Ten
   similar document findings add little more than three; critical findings always count in full.
3. `score = round(100 × (1 − Π(1 − wᵢ)))`.
4. Caps:
   - without a critical finding the score is at most **89**;
   - when, moreover, every counted finding is document or metadata exposure (categories
     documents, people and software, except software seen on the site or as a server-side
     generator), the score is at most **75**. Leaked metadata alone never reads as 100/100.

## Levels

| Score | Level |
|---|---|
| 90 and more, with a critical finding | Critical |
| 70 and more | High |
| 40 and more | Medium |
| below 40 | Low |

No score ("no data") until a scan has finished the Analysis stage or documents were analysed.

## Example

A university site with 39 high, 56 medium, 59 low and 191 info findings, all from documents
and their metadata, scored 100 with the old product formula. With the dampening per category it
scores 72 (High), and more findings of the same kinds stop at the exposure cap of 75.
