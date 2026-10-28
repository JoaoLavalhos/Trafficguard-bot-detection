# Security notes

- Nao publique `data/dados_acesso.json`, `data/config.json`, `.env` ou qualquer log real.
- O dashboard deve ser exposto somente por HTTPS.
- Prefira `TRAFFICGUARD_ADMIN_PASSWORD_HASH` a senha em texto puro.
- `TRAFFICGUARD_TRUST_PROXY_HEADERS=1` deve ser usado somente quando o servidor estiver atras de proxy/CDN confiavel configurado pelo operador.
- A verificacao de servicos locais e recursos experimentais devem permanecer desativados quando nao forem necessarios.
