# TrafficGuard

Sistema experimental de **deteccao de automacao e analise de trafego web**, desenvolvido em PHP e JavaScript com apoio de ferramentas de IA. O projeto combina sinais do servidor, consistencia do navegador, comportamento, desafios client-side e um motor de risco baseado em score.

> Projeto de portfolio e laboratorio tecnico. Nao substitui um WAF, anti-DDoS ou solucao comercial de bot management.

Os testes praticos do projeto foram executados em ambiente de hospedagem na Hostinger, com comparacao de fluxos de navegadores reais e trafego automatizado.

## Principais recursos

- analise server-side de headers HTTP, User-Agent, Client Hints, referer, metadados de sessao e contexto da requisicao;
- identificacao de assinaturas conhecidas de automacao e ambientes headless;
- reverse DNS e informacoes de rede/ASN como sinais auxiliares;
- preflight de cookies HTTP + JavaScript;
- desafio de Proof-of-Work com WebCrypto/SHA-256;
- verificacao de recurso dinamico entre navegador e servidor;
- sinais de renderizacao, viewport, APIs do navegador e comportamento;
- Audio API como sinal auxiliar de consistencia;
- MediaCapabilities e Payment Request como experimentos opcionais;
- WebRTC/ICE em modo minimizado, sem transmitir IPs/portas/SDP brutos;
- verificacao experimental e opt-in de servicos locais associados a depuracao/automacao;
- dashboard de auditoria com score, checks, motivos e detalhes tecnicos;
- autenticacao do dashboard por variavel de ambiente e protecao CSRF.

## Arquitetura do fluxo

```text
Requisicao
   |
   v
Filtros e telemetria server-side
   |
   v
Preflight HTTP / JavaScript
   |
   v
Stage 1 - render e integridade basica
   |
   v
Stage 2 - sinais client-side e Proof-of-Work
   |
   v
Motor de risco / score
   |------------------|
   v                  v
Permitido           Bloqueado
conteudo real       HTTP 403 neutro
```

A demonstracao em `index.php` inclui `tracker.php` antes do conteudo. Quando a sessao e aprovada, o tracker retorna o controle ao arquivo chamador e a pagina protegida e renderizada.

## Estrutura

```text
TrafficGuard/
├── index.php                 # pagina de demonstracao protegida
├── tracker.php               # motor de deteccao e validacao
├── dashboard.php             # monitor e configuracoes
├── config.example.json       # exemplo de configuracao
├── .env.example              # variaveis de ambiente
├── data/
│   ├── .gitkeep
│   └── .htaccess             # bloqueia acesso HTTP direto no Apache
└── docs/
    └── experiment-summary.md # resultados agregados e anonimizados
```

## Configuracao local

Requisitos principais:

- PHP 8+
- servidor web com suporte a sessoes PHP
- HTTPS recomendado para APIs modernas do navegador
- extensao cURL para enriquecimento de rede, quando utilizada

Crie a configuracao local:

```bash
cp config.example.json data/config.json
```

Gere uma senha para o dashboard:

```bash
php -r "echo password_hash('troque-esta-senha', PASSWORD_DEFAULT), PHP_EOL;"
```

Configure o resultado em `TRAFFICGUARD_ADMIN_PASSWORD_HASH` no ambiente do servidor. Consulte `.env.example`.

Por seguranca, o repositorio ignora logs, configuracao runtime e `.env`.

## Privacidade e minimizacao

A versao publica foi ajustada para demonstrar as tecnicas sem publicar dados reais de visitantes. Os logs historicos usados nos experimentos nao fazem parte do repositorio.

Alguns sinais mais invasivos permanecem apenas como codigo experimental ou sao desativados por padrao. WebRTC e enviado ao servidor somente de forma agregada, sem enderecos ICE, portas ou SDP brutos.

## Experimentos

Durante o desenvolvimento foram comparados fluxos completos, incompletos e ambientes automatizados. Os resultados mostraram que nenhum sinal isolado e confiavel o suficiente para decidir sozinho: inclusive ambientes automatizados podem reportar `navigator.webdriver = false`.

Por isso, o projeto utiliza **combinacao de sinais + score**, e diferencia checks informativos, experimentais e de maior confianca.

Um resumo anonimizado esta em [`docs/experiment-summary.md`](docs/experiment-summary.md).

## Desenvolvimento assistido por IA

Ferramentas de IA foram utilizadas como apoio para iteracao de codigo, investigacao de APIs do navegador, organizacao de hipoteses e diagnostico de fluxos. As decisoes de teste e ajustes foram refinadas a partir de execucoes e comparacao dos resultados observados.

## Observacao

Este repositorio apresenta o projeto como sistema defensivo de deteccao e analise de trafego. A versao publica retorna uma resposta neutra para acessos bloqueados e nao implementa mecanismos de entrega diferenciada de conteudo destinados a contornar revisao ou moderacao de plataformas.