# Resumo dos experimentos

Este documento registra observacoes agregadas de uma amostra historica usada durante o desenvolvimento e testada em ambiente hospedado na Hostinger. Os logs brutos nao fazem parte do repositorio porque continham IPs, User-Agents, referers e outros dados de acesso.

## Amostra analisada

- 131 registros de log; os registros representam etapas/decisoes e nao 131 visitantes unicos.
- 98 fluxos identificaveis pelo identificador de fluxo.
- 51 dos 98 fluxos nao apresentaram POST no historico capturado; 24 ficaram apenas no GET inicial. Ausencia de POST e tratada como sinal de fluxo incompleto, nunca como prova isolada de automacao.

## Sinais que se mostraram complementares

Um cluster observado em seis IPs e seis IDs de visitante diferentes apresentou o mesmo fingerprint de renderizacao de audio e terminou bloqueado em todos os seis registros. Nesse mesmo cluster apareceram, de forma recorrente, combinacoes como:

- `navigator.webdriver = false`, mostrando que esse campo sozinho nao e suficiente;
- resultado repetitivo de Audio API;
- erros consistentes em Payment Request;
- memoria reportada muito alta para o perfil apresentado;
- RTT reportado como zero;
- bateria em 100% e carregando;
- ausencia de movimento em perfis que simulavam dispositivo movel;
- servicos locais de depuracao/automacao acessiveis em parte, mas nao em todos, os casos.

Outro fingerprint de audio apareceu em diversos acessos permitidos. Isso reforcou a decisao de nunca bloquear exclusivamente por fingerprint: o motor usa combinacao de sinais e score.

## Decisoes para a versao publica

- WebRTC transmite apenas resumo de candidatos ICE; enderecos, portas e SDP brutos sao removidos antes do envio ao servidor.
- A verificacao de portas locais permanece como recurso experimental e vem desativada por padrao.
- Payment Request e MediaCapabilities permanecem como experimentos opt-in.
- O dashboard exige autenticacao e CSRF.
- Bloqueios retornam uma pagina neutra HTTP 403; a versao publica nao implementa entrega de conteudo alternativo.
