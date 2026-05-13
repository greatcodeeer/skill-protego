# Multilingual Incantations & Report Templates

This file holds pre-translated opening incantations and report templates for the 7 most-common languages. For other languages, follow the same structure and translate accurately while keeping the charm name `Protego` in its original Latin form (just like every official Harry Potter translation does).

## Opening incantation

Always 3 lines: charm cry → shield rises → searching for Dark Arts.

### 🇨🇳 Chinese (Simplified)
```
✨ Protego! ✨
你的项目周身泛起微光，一面护盾缓缓升起。
搜寻其中潜伏的黑魔法……
```

### 🇹🇼 Chinese (Traditional)
```
✨ Protego! ✨
你的專案周身泛起微光，一面護盾緩緩升起。
搜尋其中潛伏的黑魔法……
```

### 🇺🇸 English
```
✨ Protego! ✨
A shimmering shield rises around your project.
Searching for the Dark Arts within...
```

### 🇯🇵 Japanese
```
✨ プロテゴ！ ✨
プロジェクトを包む、輝く盾が立ち昇る。
内に潜む闇の魔術を探す……
```

### 🇰🇷 Korean
```
✨ 프로테고! ✨
당신의 프로젝트 위로 빛나는 방패가 솟아오릅니다.
그 안에 숨어 있는 어둠의 마법을 찾는 중……
```

### 🇪🇸 Spanish
```
✨ ¡Protego! ✨
Un escudo brillante se alza alrededor de tu proyecto.
Buscando las Artes Oscuras en su interior...
```

### 🇫🇷 French
```
✨ Protego ! ✨
Un bouclier scintillant s'élève autour de votre projet.
Recherche des Arts Maléfiques en cours...
```

### 🇩🇪 German
```
✨ Protego! ✨
Ein schimmernder Schild erhebt sich um Ihr Projekt.
Suche nach den Dunklen Künsten...
```

For any other language: replicate the same 3-line structure. The charm `Protego` stays in Latin; the rest gets translated. The tone should evoke a wizarding incantation — slightly archaic, ceremonial — not corporate-tool-language.

---

## Confirmation prompts (Step 2 of workflow)

Pre-scan confirmation must be in the user's language. Templates:

### 🇨🇳
```
⚠️ 即将对 `<path>` 施展 Protego 安全审计。

扫描范围：
  • A 层 — 依赖供应链（7 个维度，覆盖 npm/PyPI/Cargo/CocoaPods 等）
  • B 层 — 项目源码（5 个维度：密钥/注入 sink/配置暴露/git 历史/架构反模式）

预计耗时：30 秒 – 3 分钟，视项目规模而定。
检测到的生态：<ecosystems>

确认开始扫描吗？（yes / no）
```

### 🇺🇸
```
⚠️ Ready to cast Protego over `<path>`.

Scope:
  • Layer A — Dependency supply-chain (7 dimensions, covers npm/PyPI/Cargo/CocoaPods/...)
  • Layer B — Project source code (5 dimensions: secrets / injection sinks / config exposure / git history / architectural anti-patterns)

Estimated time: 30s – 3min depending on project size.
Detected ecosystems: <ecosystems>

Confirm to proceed? (yes / no)
```

### 🇯🇵
```
⚠️ `<path>` に Protego を唱える準備が整いました。

スキャン範囲：
  • レイヤー A — 依存関係サプライチェーン（7 次元、npm/PyPI/Cargo/CocoaPods など）
  • レイヤー B — プロジェクトのソースコード（5 次元：秘密鍵 / インジェクション / 設定漏洩 / git 履歴 / アーキテクチャ）

所要時間：30 秒〜3 分（プロジェクト規模による）。
検出されたエコシステム：<ecosystems>

実行してよろしいですか？（yes / no）
```

### 🇰🇷
```
⚠️ `<path>`에 Protego를 시전할 준비가 되었습니다.

스캔 범위:
  • 레이어 A — 의존성 공급망 (7개 차원: npm/PyPI/Cargo/CocoaPods 등)
  • 레이어 B — 프로젝트 소스 코드 (5개 차원: 비밀키 / 인젝션 sink / 설정 노출 / git 이력 / 아키텍처)

예상 소요 시간: 30초 ~ 3분 (프로젝트 규모에 따라 다름).
감지된 생태계: <ecosystems>

계속 진행할까요? (yes / no)
```

### 🇪🇸
```
⚠️ Listo para lanzar Protego sobre `<path>`.

Alcance:
  • Capa A — Cadena de suministro de dependencias (7 dimensiones: npm/PyPI/Cargo/CocoaPods...)
  • Capa B — Código fuente (5 dimensiones: secretos / inyecciones / exposición de config / historial git / antipatrones)

Tiempo estimado: 30s – 3min según el tamaño del proyecto.
Ecosistemas detectados: <ecosystems>

¿Confirmas el escaneo? (sí / no)
```

### 🇫🇷
```
⚠️ Prêt à lancer Protego sur `<path>`.

Portée :
  • Couche A — Chaîne d'approvisionnement (7 dimensions : npm/PyPI/Cargo/CocoaPods…)
  • Couche B — Code source du projet (5 dimensions : secrets / injections / fuites de config / historique git / anti-patterns)

Durée estimée : 30 s – 3 min selon la taille du projet.
Écosystèmes détectés : <ecosystems>

Confirmer le scan ? (oui / non)
```

### 🇩🇪
```
⚠️ Bereit, Protego über `<path>` zu sprechen.

Umfang:
  • Ebene A — Abhängigkeits-Lieferkette (7 Dimensionen: npm/PyPI/Cargo/CocoaPods…)
  • Ebene B — Projekt-Quellcode (5 Dimensionen: Geheimnisse / Injektionen / Konfigurationslecks / Git-Historie / Anti-Patterns)

Geschätzte Zeit: 30 s – 3 min je nach Projektgröße.
Erkannte Ökosysteme: <ecosystems>

Scan starten? (ja / nein)
```

---

## Report verdict lines

After the scanner exits, render one of these verdict lines first, in the user's language:

### 🟢 PASS

| Lang | Text |
|---|---|
| 🇨🇳 | 🟢 **审计通过** — 未发现可疑模式。继续保持。 |
| 🇺🇸 | 🟢 **AUDIT PASSED** — no suspicious patterns detected. Keep it up. |
| 🇯🇵 | 🟢 **監査合格** — 疑わしいパターンは検出されませんでした。 |
| 🇰🇷 | 🟢 **감사 통과** — 의심스러운 패턴이 감지되지 않았습니다. |
| 🇪🇸 | 🟢 **AUDITORÍA APROBADA** — no se detectaron patrones sospechosos. |
| 🇫🇷 | 🟢 **AUDIT RÉUSSI** — aucun motif suspect détecté. |
| 🇩🇪 | 🟢 **AUDIT BESTANDEN** — keine verdächtigen Muster gefunden. |

### 🟡 WARNINGS ONLY

| Lang | Text |
|---|---|
| 🇨🇳 | 🟡 **仅有警告** — 发现 N 个非阻断问题，建议处理但不必立即阻止部署。 |
| 🇺🇸 | 🟡 **WARNINGS ONLY** — N non-blocking issues found. Address when you can. |
| 🇯🇵 | 🟡 **警告のみ** — N 件の非ブロッキングな問題が見つかりました。 |
| 🇰🇷 | 🟡 **경고만 있음** — N개의 비차단성 문제가 발견되었습니다. |
| 🇪🇸 | 🟡 **SOLO ADVERTENCIAS** — N problemas no bloqueantes encontrados. |
| 🇫🇷 | 🟡 **AVERTISSEMENTS UNIQUEMENT** — N problèmes non bloquants trouvés. |
| 🇩🇪 | 🟡 **NUR WARNUNGEN** — N nicht-blockierende Probleme gefunden. |

### 🔴 BLOCKED

| Lang | Text |
|---|---|
| 🇨🇳 | 🔴 **审计阻断** — 发现 N 个阻断级问题（+ M 个警告）。**不要部署 / 发布 / 提交，直至处理完毕**。 |
| 🇺🇸 | 🔴 **AUDIT BLOCKED** — N blocking issues (+ M warnings). **Do NOT deploy / publish / commit until addressed.** |
| 🇯🇵 | 🔴 **監査ブロック** — N 件の重大な問題（+ M 件の警告）。**修正するまでデプロイ / 公開しないでください**。 |
| 🇰🇷 | 🔴 **감사 차단** — N개의 차단성 문제 (+ M개의 경고). **해결 전까지 배포 / 게시 / 커밋 금지**. |
| 🇪🇸 | 🔴 **AUDITORÍA BLOQUEADA** — N problemas bloqueantes (+ M advertencias). **NO despliegues / publiques / commits hasta resolverlos**. |
| 🇫🇷 | 🔴 **AUDIT BLOQUÉ** — N problèmes bloquants (+ M avertissements). **NE PAS déployer / publier / commit avant résolution**. |
| 🇩🇪 | 🔴 **AUDIT BLOCKIERT** — N blockierende Probleme (+ M Warnungen). **NICHT deployen / veröffentlichen / committen bis behoben**. |

---

## Finding formatting

For each finding, format as:

```
<icon> <dimension>.<id> — <title>
   📄 <file>:<line>
   ⟶ <evidence (truncated)>
   <explanation, translated to user's language>
```

Where `<icon>` is 🔴 for blocking, 🟡 for warning.

Group by dimension (A1, A2, ..., B5) so the user sees the structure.

End with a "Recommendations" section in the user's language listing concrete next actions (rotate keys, remove file from git, update lockfile, add pnpm gate, etc.).
