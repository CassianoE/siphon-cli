# PROBLEMS.md — Auditoria Completa Siphon (QA Round 3)

**Data:** 2026-02-25
**Commit:** (sem commits — branch master vazia)
**Total de problemas:** 18
**Por severidade:** Critical: 0 | High: 3 | Medium: 8 | Low: 7
**Por categoria:** Build: 1 | Runtime: 4 | Logic: 5 | Design: 5 | Security: 2 | Test: 1

**Veredicto geral:** O projeto compila, builda em release, e roda end-to-end com sucesso. Os 94 testes passam. O pipeline completo funciona: URL → browser → captura → análise → geração de script. Scripts Python e curl gerados são sintaticamente válidos e executam corretamente. Nenhum problema critical encontrado. Os problemas high são de segurança (JS injection), funcionalidade faltante (--timeout não implementado) e bug no action parser (vírgula no valor). Estimativa de completude: ~90%.

---

## [P-001] `--timeout` CLI arg is declared but never used
- **Severidade:** high
- **Categoria:** runtime
- **Onde:** `src/main.rs:42-43` (declaração), `src/browser.rs` (todo o arquivo)
- **Reproduzir:** `cargo run -- "https://httpbin.org/get" --timeout 1` — o timeout é ignorado
- **Esperado:** O browser deveria respeitar o timeout configurado e abortar se a operação demorar mais
- **Atual:** O valor é parseado pelo clap e exibido no verbose mode (linha 93: `println!("{} {}s", "Timeout:".bold(), cli.timeout)`), mas nunca é passado para `SiphonBrowser::launch()`, `navigate()`, `execute_actions()`, ou qualquer operação CDP. Se o site travar, o siphon espera indefinidamente.
- **Notas:** O `SiphonBrowser` não tem nenhum parâmetro de timeout. Seria necessário adicionar `tokio::time::timeout()` wrapping as chamadas de navegação e execução de ações.

---

## [P-002] JS injection vulnerability em Select e Submit actions
- **Severidade:** high
- **Categoria:** security
- **Onde:** `src/browser.rs:282-292` (Select), `src/browser.rs:310-316` (Submit)
- **Reproduzir:** `cargo run -- "https://example.com" --actions "select:'); alert(1);//=val"`
- **Esperado:** O selector deveria ser sanitizado ou escapado corretamente para contexto JS
- **Atual:** O selector e value são interpolados direto no `format!()` que gera JavaScript executado via `page.evaluate()`. Apenas single quotes são escapadas (`replace('\'', "\\'")`), mas não há escape de `}`, `)`, `;`, ou backticks. Um selector malicioso pode quebrar a string e injetar JS arbitrário no contexto da página.
- **Notas:** Isto é executado no contexto headless do próprio usuário, então o risco prático é baixo (self-XSS), mas o princípio é incorreto. O correto seria usar `document.querySelector()` via CDP `Runtime.callFunctionOn` com argumentos passados separadamente, ou no mínimo escapar backslash, newlines, e outros caracteres especiais.

---

## [P-003] Comma na action value causa parse error
- **Severidade:** high
- **Categoria:** logic
- **Onde:** `src/actions.rs:90` (split por vírgula)
- **Reproduzir:** `cargo run -- "https://httpbin.org/get" --actions "type:#email=test@test,com"`
- **Esperado:** A vírgula dentro do valor deveria ser preservada; o valor deveria ser `test@test,com`
- **Atual:** `Invalid action format 'com'. Expected 'verb:target'` — a vírgula no valor é interpretada como separador de ações, e `com` sozinho não tem formato `verb:target`.
- **Notas:** O `parse_actions` faz `input.split(',')` para suportar múltiplas ações em uma string, mas isso quebra valores que contêm vírgula. A solução seria escapar vírgulas ou usar um separador diferente, ou ser bracket/quote-aware no split, ou simplesmente rely on clap's `num_args` para múltiplas actions (cada `--actions` arg = 1 action, elimina necessidade do comma-split).

---

## [P-004] Warning de output format aparece antes do banner
- **Severidade:** low
- **Categoria:** design
- **Onde:** `src/main.rs:70-76`
- **Reproduzir:** `cargo run -- "https://httpbin.org/get" --output blah`
- **Esperado:** O banner deveria aparecer primeiro, depois o warning
- **Atual:**
  ```
    ⚠ Unknown output format 'blah', defaulting to python
  ╔═══════════════════════════════════════╗
  ║        Siphon — Flow Extractor        ║
  ╚═══════════════════════════════════════╝
  ```
  O warning fica perdido antes do banner.
- **Notas:** Mover o bloco de validação (linhas 70-76) para depois do banner (depois da linha ~83).

---

## [P-005] XHR hook não captura request headers
- **Severidade:** medium
- **Categoria:** logic
- **Onde:** `src/hooks.rs:37-60` (XHR_HOOK)
- **Reproduzir:** Qualquer site que use `XMLHttpRequest` com headers customizados (ex: `xhr.setRequestHeader('X-CSRF-Token', 'abc')`)
- **Esperado:** Os headers do request deveriam ser capturados no `__siphon_requests`
- **Atual:** O XHR hook intercepta `open` e `send`, mas não intercepta `setRequestHeader`. O objeto `__siphon` salva `method`, `url`, `body`, `timestamp`, `type`, `responseStatus`, `responseBody`, mas não `headers`. O campo `headers` nunca é populado no hook XHR (diferente do fetch hook que captura `args[1].headers`).
- **Notas:** Seria necessário interceptar `XMLHttpRequest.prototype.setRequestHeader` para acumular os headers num objeto/array no `this.__siphon.headers`. Impacto prático é baixo porque o CDP Network events já captura headers; o JS hook é redundância.

---

## [P-006] Fetch hook não trata Headers object corretamente
- **Severidade:** medium
- **Categoria:** logic
- **Onde:** `src/hooks.rs:18` (`headers: (args[1] && args[1].headers) || {}`)
- **Reproduzir:** Site que use `fetch(url, { headers: new Headers({'X-Token': 'abc'}) })`
- **Esperado:** Os headers deveriam ser convertidos para objeto plain e capturados
- **Atual:** Se os headers forem um `Headers` object (API nativa do browser), o hook salva o object reference, mas `JSON.stringify()` de um `Headers` object produz `{}` (objeto vazio). Apenas headers passados como objeto literal plain são capturados corretamente.
- **Notas:** Seria necessário: `if (h instanceof Headers) { const obj = {}; h.forEach((v,k) => obj[k] = v); }`. Impacto prático é baixo pelo mesmo motivo do P-005 (CDP captura tudo).

---

## [P-007] `dedup_by` não remove duplicatas não-consecutivas
- **Severidade:** medium
- **Categoria:** logic
- **Onde:** `src/capture.rs:54`
- **Reproduzir:** Três requests: A(t=1), B(t=2), A(t=3) com mesmo method+url+body para A
- **Esperado:** Deveria manter apenas um A e um B (2 requests)
- **Atual:** `dedup_by` do Rust remove apenas duplicatas **consecutivas** (como `uniq` do shell). Como a lista é sorted por timestamp (linha 51), e os dois A's estão separados por B no tempo, o segundo A não será removido: `[A, B, A]` → `[A, B, A]` (3 requests, sem mudança).
- **Notas:** Para dedup real, usar `HashSet` com (method, url, body) como chave, ou `sort_by` + `dedup_by` com a mesma key. Os testes existentes passam porque os duplicados têm o mesmo timestamp e ficam adjacentes após o sort.

---

## [P-008] Regex compilada a cada chamada em hot path
- **Severidade:** medium
- **Categoria:** runtime
- **Onde:** `src/analyzer.rs:184-194` (3x `Regex::new`), `src/analyzer.rs:256-264` (2x `Regex::new`)
- **Reproduzir:** Qualquer execução com múltiplos requests capturados
- **Esperado:** Regex deveria ser compilada uma vez (`lazy_static` ou `OnceLock`)
- **Atual:** Para cada request na lista, `extract_tokens_from_response` é chamada, que chama `extract_html_tokens` e `extract_regex_tokens`, cada uma compilando 2-3 regexes do zero com `Regex::new().unwrap()`. Para 50 requests, são 250 compilações de regex desnecessárias.
- **Notas:** Performance issue apenas. Com poucos requests (<20), impacto é negligível. Idealmente usar `std::sync::LazyLock` (stable desde Rust 1.80).

---

## [P-009] `Regex::new().unwrap()` em código de produção
- **Severidade:** low
- **Categoria:** runtime
- **Onde:** `src/analyzer.rs:184,188,192,258,262`
- **Reproduzir:** Não reproduzível em runtime normal (as regexes são string literals válidas)
- **Esperado:** Regex errors deveriam ser tratados gracefully, ou garantidos em compile-time
- **Atual:** 5 chamadas `Regex::new(...).unwrap()` em código não-test. Se a regex fosse inválida, causaria panic em runtime. Como as regexes são literais constantes, isso nunca vai acontecer na prática, mas é má prática.
- **Notas:** Converter para `LazyLock` resolveria tanto P-008 quanto P-009 simultaneamente.

---

## [P-010] `OutputFormat::from_str` shadows o trait `std::str::FromStr`
- **Severidade:** low
- **Categoria:** design
- **Onde:** `src/types.rs:139`
- **Reproduzir:** N/A — funciona como inherent method, mas impede implementação futura do trait
- **Esperado:** Deveria implementar `impl FromStr for OutputFormat` ou renomear para evitar ambiguidade
- **Atual:** É um método inherent `fn from_str(s: &str) -> Self` que nunca falha (retorna Python como default). Isso funciona mas: (1) shadow do nome do trait padrão, (2) impossibilita usar `"python".parse::<OutputFormat>()`, (3) confunde leitores do código.
- **Notas:** Poderia ser renomeado para `from_str_or_default` ou implementar `FromStr` properly com `type Err = String`.

---

## [P-011] `exclude_static` é hardcoded `true`, sem CLI flag para desativar
- **Severidade:** medium
- **Categoria:** design
- **Onde:** `src/capture.rs:38`, `src/main.rs` (sem `--include-static` flag)
- **Reproduzir:** `cargo run -- "https://example.com" --include-static` → error: unexpected argument
- **Esperado:** Deveria haver um `--include-static` flag para capturar assets estáticos quando desejado
- **Atual:** `RequestFilter::new()` sempre cria com `exclude_static: true`. O campo `exclude_static` existe no struct mas não há forma de setá-lo para `false` via CLI.
- **Notas:** Adicionar `#[arg(long)] include_static: bool` ao Cli struct e passá-lo para o filter.

---

## [P-012] Clippy reporta 10 warnings
- **Severidade:** low
- **Categoria:** build
- **Onde:** Múltiplos arquivos
- **Reproduzir:** `cargo clippy`
- **Esperado:** Zero warnings
- **Atual:** 10 warnings:
  - 7x `empty_line_after_doc_comments` (actions.rs, analyzer.rs, browser.rs, capture.rs, classifier.rs, codegen.rs, hooks.rs) — `///` doc comments deveriam ser `//!` module-level comments
  - 1x `needless_range_loop` (analyzer.rs:39) — iterator+enumerate preferível a indexing
  - 1x `useless_format` (codegen.rs:186) — `format!()` em string literal, deveria ser `.to_string()`
  - 1x `doc_lazy_continuation` (hooks.rs:9) — doc comment formatting
- **Notas:** Nenhum é funcional. Todos são estilo/idiomático Rust.

---

## [P-013] Curl template: `trap` com double quotes
- **Severidade:** low
- **Categoria:** logic
- **Onde:** `src/templates/curl.tera:6`
- **Reproduzir:** Gerar curl script e inspecionar a linha de trap
- **Esperado:** Expansão de variável no trap deveria ser lazy (single quotes)
- **Atual:** `trap "rm -f $COOKIE_JAR" EXIT` — com double quotes, `$COOKIE_JAR` é expandido no momento da declaração do trap, não na execução. Na prática funciona porque o valor do `mktemp` já está definido nesse ponto.
- **Notas:** Melhor prática shell seria `trap 'rm -f "$COOKIE_JAR"' EXIT`. Impacto prático zero no código atual.

---

## [P-014] Curl template: `grep -oP` não funciona no macOS
- **Severidade:** medium
- **Categoria:** runtime
- **Onde:** `src/templates/curl.tera:37`
- **Reproduzir:** Gerar curl script com HTML/regex extraction em macOS e executar
- **Esperado:** O grep deveria funcionar em macOS
- **Atual:** `grep -oP '{{ ext.regex_pattern }}' | head -1` — a flag `-P` (Perl regex) não está disponível no `grep` do macOS (BSD grep). Falha com `grep: invalid option -- P`. Este path é executado quando há extrações do tipo `html` ou `regex`.
- **Notas:** Alternativas: usar `grep -oE` (extended regex, requer adaptar os patterns), ou usar `perl -nle` ou `python3 -c` como fallback. Afeta qualquer macOS user que gere scripts com extrações HTML/regex.

---

## [P-015] Browser `close()` consome self — impede RAII cleanup
- **Severidade:** low
- **Categoria:** design
- **Onde:** `src/browser.rs:474` (`pub async fn close(mut self)`)
- **Reproduzir:** N/A — design issue
- **Esperado:** O browser deveria ser cleanup automaticamente via `Drop` ou RAII
- **Atual:** `close()` consome `self` (takes ownership), tornando impossível implementar `Drop` ou usar em múltiplos error paths sem `clone()`. Em `main.rs`, cada error path precisa chamar `siphon_browser.close()` manualmente antes de `process::exit(1)`.
- **Notas:** Na prática, o processo terminando mata os child processes do Chrome. Testes manuais confirmaram que processos Chrome são limpos corretamente (verificado com `ps aux` — 6 processos chrome pre-existentes, nenhum novo após erro). Um pattern melhor seria `Arc<SiphonBrowser>` com `Drop` impl, ou `scopeguard`.

---

## [P-016] Fetch hook não trata erro no `clone().text()`
- **Severidade:** low
- **Categoria:** logic
- **Onde:** `src/hooks.rs:24-29`
- **Reproduzir:** Fetch que retorne stream já consumido ou body locked
- **Esperado:** O hook deveria tratar erros gracefully
- **Atual:** O fetch hook faz `clone.text().then(body => ...)` mas não tem `.catch()`. Se `clone.text()` falhar, a promise rejeitada gera `Unhandled Promise Rejection` no console do browser, e o request não é adicionado a `__siphon_requests`.
- **Notas:** Adicionar `.catch(() => {})` após o `.then()`. Impacto prático baixo — CDP Network events é o mecanismo primário.

---

## [P-017] Action parser não valida formato de seletores CSS
- **Severidade:** low
- **Categoria:** design
- **Onde:** `src/actions.rs:40`
- **Reproduzir:** `cargo run -- "https://example.com" --actions "click:not-a-valid-css!!!"` — aceita sem warning no parse, falha no Step 4
- **Esperado:** Warning ou validação básica na etapa de parse
- **Atual:** Qualquer string é aceita como selector no parse. O erro só aparece no Step 4 quando o browser tenta encontrar o elemento. A mensagem agora é clara ("Element not found: 'selector'").
- **Notas:** Design choice válida — seletores CSS complexos são difíceis de validar sem parser completo. O erro no runtime é claro o suficiente.

---

## [P-018] `Script` resource type não está no filtro de static assets
- **Severidade:** medium
- **Categoria:** logic
- **Onde:** `src/capture.rs:25-32` (`STATIC_RESOURCE_TYPES`)
- **Reproduzir:** Navegar em site que carrega scripts externos sem extensão `.js` na URL
- **Esperado:** Scripts JS deveriam ser filtrados como static assets
- **Atual:** `STATIC_RESOURCE_TYPES` inclui `Stylesheet`, `Image`, `Font`, `Media`, `Manifest`, `Other`, mas **não inclui `Script`**. A filtragem por extensão URL (`.js` em `STATIC_EXTENSIONS`) pega a maioria dos scripts, mas scripts servidos sem `.js` na URL (ex: `https://cdn.example.com/bundle?v=123`, inline `data:` URLs) passam pelo filtro e poluem o output.
- **Notas:** Adicionar `"Script"` ao `STATIC_RESOURCE_TYPES`. Na captura real do httpbin.org, os scripts foram filtrados pela extensão `.js`, então o impacto não apareceu nos testes E2E.

---

# O que funciona bem

- **Pipeline completo E2E**: URL → browser → captura → análise → codegen funciona de ponta a ponta com httpbin.org
- **Qualidade dos testes**: 94 testes cobrindo todos os módulos. Testes são substantivos, não triviais — testam edge cases reais (bracket-aware parsing, URL-encoded body matching, JWT priority over name, backward dependency prevention, etc.)
- **Output legível**: Terminal output com cores, steps numerados, e uso de `plural()` é claro e profissional
- **Scripts gerados válidos**: Python e curl geram código sintaticamente válido (verificado com `ast.parse()` e `bash -n`) que executa corretamente
- **Error handling no pipeline**: Erros de navegação, seletor não encontrado, URL inválida, e DNS failure produzem mensagens claras e amigáveis
- **Dependency detection**: O analyzer detecta corretamente tokens em JSON bodies, Set-Cookie headers, HTML meta tags, hidden inputs, inline JS, e URL query params
- **Template system**: Tera templates bem estruturados com injection placeholders corretos (Python f-strings, bash `$VAR`)
- **Dual capture**: CDP Network events + JS hooks fornecem redundância na captura de requests
- **Token classification**: Classifier com prioridade correta (JWT > OAuth > CSRF > Session > ApiKey > Nonce > Unknown) com entropy-based fallback
- **Browser cleanup**: Processos Chrome são limpos corretamente em operação normal (verificado manualmente com `ps aux`)
- **Build system**: Compila sem erros em dev e release. Todas as dependências resolvem. Cargo.toml limpo e correto
- **Action parser**: Bracket-aware splitting funciona corretamente para seletores CSS complexos como `input[name=email]=value`
