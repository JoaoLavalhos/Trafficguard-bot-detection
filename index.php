<?php
require __DIR__ . '/tracker.php';
?>
<!doctype html>
<html lang="pt-br">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>TrafficGuard | Demo</title>
    <style>
        * { box-sizing: border-box; }
        body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f5f7fb; color: #1f2937; font-family: system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif; }
        main { width: min(760px, calc(100% - 32px)); background: #fff; border: 1px solid #e5e7eb; border-radius: 18px; padding: 36px; box-shadow: 0 14px 50px rgba(15,23,42,.08); }
        .tag { display: inline-block; padding: 6px 10px; border-radius: 999px; background: #e8f1ff; color: #0d6efd; font-size: .8rem; font-weight: 700; }
        h1 { margin: 14px 0 10px; }
        p { color: #64748b; line-height: 1.6; }
        code { background: #f1f5f9; padding: 2px 6px; border-radius: 5px; }
    </style>
</head>
<body>
<main>
    <span class="tag">Sessao validada</span>
    <h1>TrafficGuard</h1>
    <p>Esta pagina de demonstracao so e renderizada depois que o fluxo de validacao do <code>tracker.php</code> conclui. Em uma aplicacao real, o conteudo protegido entraria neste ponto.</p>
</main>
</body>
</html>
