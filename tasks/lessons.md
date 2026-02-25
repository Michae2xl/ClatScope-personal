# OrbisInt — Lições Aprendidas

Registro de padrões, erros e boas práticas identificados durante o desenvolvimento.
Atualizado continuamente para evitar repetição de erros.

---

## L01 — Erro de sintaxe JavaScript no template HTML
**Contexto:** O app não respondia a cliques no menu após o primeiro deploy.
**Causa raiz:** String com aspas simples dentro de atribuição JavaScript em template Jinja2 gerou erro de sintaxe silencioso — o script inteiro falhava ao carregar.
**Solução:** Usar aspas duplas em atribuições JS dentro de templates, ou escapar corretamente. Sempre validar o JS extraído com `node --check` após edições no HTML.
**Regra:** Após qualquer edição no bloco `<script>` do template, executar validação de sintaxe JS antes de reiniciar o servidor.

---

## L02 — GitHub bloqueou push com API keys expostas
**Contexto:** Tentativa de commit com `api_credentials.md` e `config.json` contendo chaves reais.
**Causa raiz:** GitHub Secret Scanning detectou o padrão `pplx-` (Perplexity) e bloqueou o push.
**Solução:** Adicionar `config.json` e `api_credentials.md` ao `.gitignore` imediatamente após criação. Resetar o commit com `git reset HEAD~1` antes de tentar novo push.
**Regra:** Arquivos com credenciais NUNCA devem ser rastreados pelo git. Criar `.gitignore` antes de criar os arquivos de configuração.

---

## L03 — Números temporários públicos bloqueados pelo Hunter.io
**Contexto:** Tentativa de verificação por SMS no Hunter.io usando receive-smss.com.
**Causa raiz:** O Hunter.io mantém blocklist de números VoIP e números já usados por outras contas.
**Solução:** Para serviços que exigem SMS único, usar número pessoal do usuário ou serviço de número virtual pago (TextNow, Google Voice).
**Regra:** Não tentar receive-smss.com para serviços que exigem verificação de identidade por telefone.

---

## L04 — Veriphone retornava "Account inactive" após cadastro
**Contexto:** API key do Veriphone configurada mas retornando erro de conta inativa.
**Causa raiz:** O Veriphone exige confirmação de e-mail antes de ativar a API key, mesmo que o login funcione.
**Solução:** Aguardar o usuário confirmar o e-mail antes de testar a API. O painel do Veriphone mostra "FREE plan ativo" apenas após a confirmação.
**Regra:** Para APIs com confirmação de e-mail obrigatória, sempre verificar o status no painel web antes de declarar a API como configurada.

---

## L05 — VirusTotal e NumVerify bloqueiam cadastro automático com reCAPTCHA
**Contexto:** Tentativa de criar contas automaticamente via browser automation.
**Causa raiz:** Google reCAPTCHA v2 (seleção de imagens) não pode ser resolvido por automação.
**Solução:** Para esses serviços, orientar o usuário a criar a conta manualmente e enviar apenas a API key.
**Regra:** Não tentar resolver reCAPTCHA visual automaticamente. Identificar a presença do CAPTCHA antes de iniciar o fluxo de cadastro e pedir ajuda ao usuário imediatamente.

---

## L06 — Perplexity usa magic link (sem senha)
**Contexto:** Tentativa de login automático na Perplexity para obter a API key.
**Causa raiz:** A Perplexity não usa senha — envia um link de acesso por e-mail a cada login.
**Solução:** Solicitar ao usuário que faça login manualmente e copie a API key (começa com `pplx-`).
**Regra:** Verificar o método de autenticação do serviço antes de tentar login automático. Serviços com magic link exigem intervenção manual.

---

## L07 — Flask precisa ser reiniciado para carregar novas API keys do config.json
**Contexto:** API key adicionada ao `config.json` mas não funcionando imediatamente.
**Causa raiz:** O Flask carrega o `config.json` na inicialização, não em tempo real.
**Solução:** Sempre reiniciar o processo Flask após editar o `config.json`.
**Regra:** Após qualquer edição no `config.json`, executar `pkill -f app.py && cd webapp && nohup python3.11 app.py &` antes de testar.

---

## L08 — Domínio manus.bot não tem servidor de e-mail acessível
**Contexto:** Tentativa de acessar e-mails enviados para `zkmano@manus.bot`.
**Causa raiz:** O domínio `manus.bot` não possui MX records públicos nem webmail acessível.
**Solução:** Para serviços que enviam e-mail de verificação, usar um serviço de e-mail temporário com caixa de entrada acessível (mail.tm, guerrillamail) ou pedir ao usuário para usar seu e-mail pessoal.
**Regra:** Antes de usar um e-mail para cadastros que exigem verificação, confirmar que a caixa de entrada é acessível.
