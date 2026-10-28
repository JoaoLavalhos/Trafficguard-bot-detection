<?php
// TrafficGuard - dashboard de monitoramento e configuracao.
// Versao de portfolio com autenticacao por variavel de ambiente e protecao CSRF.

session_start();

$adminHash = trim((string)getenv('TRAFFICGUARD_ADMIN_PASSWORD_HASH'));
$adminPassword = (string)getenv('TRAFFICGUARD_ADMIN_PASSWORD');

function trafficGuardPasswordValid($candidate, $hash, $plain) {
    if ($hash !== '') return password_verify((string)$candidate, $hash);
    if ($plain !== '') return hash_equals($plain, (string)$candidate);
    return false;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'login') {
    if (trafficGuardPasswordValid($_POST['password'] ?? '', $adminHash, $adminPassword)) {
        session_regenerate_id(true);
        $_SESSION['trafficguard_admin'] = true;
        header('Location: ' . strtok($_SERVER['REQUEST_URI'] ?? 'dashboard.php', '?'));
        exit;
    }
    $loginError = 'Senha invalida.';
}

if (empty($_SESSION['trafficguard_admin'])) {
    $setupMissing = $adminHash === '' && $adminPassword === '';
    ?><!doctype html><html lang="pt-br"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TrafficGuard | Login</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f6f9;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;color:#1f2937}.box{width:min(420px,calc(100% - 32px));box-sizing:border-box;background:#fff;border:1px solid #e5e7eb;border-radius:16px;padding:28px;box-shadow:0 12px 40px rgba(15,23,42,.08)}h1{font-size:1.4rem;margin:0 0 8px}.muted{color:#64748b;font-size:.92rem;line-height:1.5}.err{color:#b91c1c;margin:12px 0}input{width:100%;box-sizing:border-box;padding:11px 12px;border:1px solid #cbd5e1;border-radius:9px;margin:8px 0 12px}button{width:100%;padding:11px;border:0;border-radius:9px;background:#0d6efd;color:#fff;font-weight:700;cursor:pointer}code{font-size:.82rem}</style></head><body><main class="box"><h1>TrafficGuard</h1><p class="muted">Acesso administrativo ao monitor de trafego.</p><?php if (!empty($loginError)): ?><div class="err"><?php echo htmlspecialchars($loginError, ENT_QUOTES, 'UTF-8'); ?></div><?php endif; ?><?php if ($setupMissing): ?><p class="muted"><strong>Configuracao necessaria:</strong> defina <code>TRAFFICGUARD_ADMIN_PASSWORD_HASH</code> (recomendado) ou <code>TRAFFICGUARD_ADMIN_PASSWORD</code> no ambiente do servidor.</p><?php else: ?><form method="post"><input type="hidden" name="action" value="login"><label for="password">Senha</label><input id="password" name="password" type="password" autocomplete="current-password" required><button type="submit">Entrar</button></form><?php endif; ?></main></body></html><?php
    exit;
}

if (empty($_SESSION['trafficguard_csrf'])) $_SESSION['trafficguard_csrf'] = bin2hex(random_bytes(32));
$csrfToken = $_SESSION['trafficguard_csrf'];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') !== 'login') {
    $postedCsrf = (string)($_POST['csrf_token'] ?? '');
    if ($postedCsrf === '' || !hash_equals($csrfToken, $postedCsrf)) {
        http_response_code(403);
        exit('CSRF token invalido.');
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'logout') {
    $_SESSION = [];
    session_destroy();
    header('Location: ' . strtok($_SERVER['REQUEST_URI'] ?? 'dashboard.php', '?'));
    exit;
}

$dataDir = __DIR__ . '/data';
if (!is_dir($dataDir)) @mkdir($dataDir, 0750, true);
$arquivoLog = $dataDir . '/dados_acesso.json';
$arquivoConfig = $dataDir . '/config.json';
$arquivoMarcas = $dataDir . '/bot_marks.json';

$defaults = [
    'lockdown' => 'off',
    'ips' => '', 'ua_keywords' => '', 'os' => '', 'referers' => '', 'countries' => '', 'isps' => '', 'queries' => '',
    'white_ips' => '', 'white_ua' => '', 'white_referers' => '', 'white_countries' => '', 'white_isps' => '', 'white_queries' => '',

    'client_checks' => 'on',
    'persistent_session' => 'off',
    'post_approved_grace_seconds' => '45',
    'technical_gate_tolerant_mode' => 'on',
    'preflight_cookie_check' => 'on',
    'required_headers_check' => 'on',
    'accept_language_keywords_check' => 'off',
    'accept_language_required_keywords' => 'pt-BR,pt',
    'device_memory_header_max_check' => 'off',
    'device_memory_header_block_min' => '16',
    'device_memory_js_max_check' => 'off',
    'device_memory_js_block_min' => '16',
    'client_min_score' => '70',
    'client_check_delay' => '1500',
    'behavior_ban_minutes' => '1440',
    'honeypot' => 'on',
    'resource_check' => 'on',
    'pow_check' => 'on',
    'motion_check' => 'on',
    'gpu_check' => 'on',
    'vibration_check' => 'on',
    'action_timing' => 'on',
    'min_action_ms' => '500',
    'render_viewport_activity_check' => 'on',
    'min_render_viewport_activity_total' => '1',
    'min_render_resize_event_count' => '0',
    'min_render_visual_resize_event_count' => '0',
    'min_render_visual_scroll_event_count' => '0',
    'render_focus_event_check' => 'on',
    'render_synthetic_click_ms_check' => 'on',
    'min_render_synthetic_click_ms' => '1',
    'max_render_synthetic_click_ms' => '3000',
    'render_service_worker_ready_check' => 'off',
    'render_service_worker_ready_expected' => 'true',
    'render_web_share_supported_check' => 'off',
    'render_web_share_supported_expected' => 'true',
    'render_payment_wallet_check' => 'off',
    'payment_request_block_error_keywords' => 'UnknownError',
    'render_media_capabilities_power_efficient_check' => 'off',
    'media_capabilities_power_efficient_false_min' => '1',
    'headless_extra_check' => 'on',
    'client_hints_check' => 'on',
    'cookie_check' => 'on',
    'pixel_ratio_check' => 'on',
    'mobile_fonts_check' => 'on',
    'timezone_check' => 'on',
    'expected_timezones' => 'America/Sao_Paulo,America/Araguaina,America/Bahia,America/Belem,America/Boa_Vista,America/Campo_Grande,America/Cuiaba,America/Eirunepe,America/Fortaleza,America/Maceio,America/Manaus,America/Noronha,America/Porto_Velho,America/Recife,America/Rio_Branco,America/Santarem',
    'network_check' => 'on',
    'battery_check' => 'on',
    'device_memory_check' => 'on',
    'audio_fingerprint_check' => 'on',
    'storage_check' => 'on',
    'pointer_check' => 'on',
    'local_debug_ports_check' => 'off',
    'whatsapp_deep_link_check' => 'off',
    'auto_bot_signatures' => 'on',
    'bot_signatures' => 'bot,crawl,slurp,spider,facebook,google,loader.io-bot,python-requests,curl,wget,httpclient,okhttp,aiohttp,scrapy,headlesschrome,playwright,selenium,puppeteer',
    'auto_datacenter' => 'on',
    'datacenter_keywords' => 'amazon,aws,google cloud,google llc,cloudflare,digitalocean,microsoft,azure,ovh,hetzner,linode,vultr,oracle,alibaba,tencent,leaseweb,colo,datacenter,hosting',
    'ja3_hashes' => ''
];

function h($value) {
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

function readJsonFile($file, $fallback = []) {
    if (!file_exists($file)) return $fallback;
    $data = json_decode(file_get_contents($file), true);
    return is_array($data) ? $data : $fallback;
}

function checkedOn($config, $key) {
    return (($config[$key] ?? 'off') === 'on') ? 'checked' : '';
}

function reasonParts($reason) {
    if (preg_match('/^BLOCKED\s*\((.*)\)$/', (string)$reason, $m)) {
        $items = array_filter(array_map('trim', explode(';', $m[1])));
        return ['blocked' => true, 'pending' => false, 'items' => $items ?: ['Bloqueado']];
    }
    if (preg_match('/^PENDING\s*\((.*)\)$/', (string)$reason, $m)) {
        $items = array_filter(array_map('trim', explode(';', $m[1])));
        return ['blocked' => false, 'pending' => true, 'items' => $items ?: ['Aguardando validacao']];
    }
    return ['blocked' => false, 'pending' => false, 'items' => [(string)$reason]];
}

function renderReason($reason) {
    $parsed = reasonParts($reason);
    if ($parsed['blocked']) {
        echo '<div class="d-flex flex-wrap gap-1 align-items-center">';
        echo '<span class="badge bg-danger badge-reason">BLOCKED</span>';
        foreach ($parsed['items'] as $item) {
            $class = stripos($item, 'LOCKDOWN') !== false ? 'bg-dark' : 'bg-danger';
            echo '<span class="badge ' . $class . ' badge-reason">' . h($item) . '</span>';
        }
        echo '</div>';
        return;
    }
    if ($parsed['pending']) {
        echo '<div class="d-flex flex-wrap gap-1 align-items-center">';
        echo '<span class="badge bg-warning text-dark badge-reason">PENDING</span>';
        foreach ($parsed['items'] as $item) {
            echo '<span class="badge bg-warning text-dark badge-reason">' . h($item) . '</span>';
        }
        echo '</div>';
        return;
    }

    $class = ($reason === 'Bot/Crawler') ? 'bg-warning text-dark' : 'bg-success';
    echo '<span class="badge ' . $class . ' badge-reason">' . h($reason) . '</span>';
}

if (isset($_GET['access_detail'])) {
    $requestedRow = (int)$_GET['access_detail'];
    $accessList = readJsonFile($arquivoLog, []);
    foreach ($accessList as $accessItem) {
        if ((int)($accessItem['row'] ?? 0) === $requestedRow) {
            header('Content-Type: application/json; charset=utf-8');
            header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
            echo json_encode($accessItem, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            exit;
        }
    }
    http_response_code(404);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error' => 'Acesso nao encontrado']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] == 'save_config') {
    $novaConfig = [
        'lockdown' => $_POST['lockdown'] ?? 'off',

        'ips' => $_POST['ips'] ?? '',
        'ua_keywords' => $_POST['ua_keywords'] ?? '',
        'os' => $_POST['os'] ?? '',
        'referers' => $_POST['referers'] ?? '',
        'countries' => $_POST['countries'] ?? '',
        'isps' => $_POST['isps'] ?? '',
        'queries' => $_POST['queries'] ?? '',

        'white_ips' => $_POST['white_ips'] ?? '',
        'white_ua' => $_POST['white_ua'] ?? '',
        'white_referers' => $_POST['white_referers'] ?? '',
        'white_countries' => $_POST['white_countries'] ?? '',
        'white_isps' => $_POST['white_isps'] ?? '',
        'white_queries' => $_POST['white_queries'] ?? '',


        'client_checks' => $_POST['client_checks'] ?? 'off',
        'persistent_session' => $_POST['persistent_session'] ?? 'off',
        'post_approved_grace_seconds' => $_POST['post_approved_grace_seconds'] ?? '45',
        'technical_gate_tolerant_mode' => $_POST['technical_gate_tolerant_mode'] ?? 'off',
        'preflight_cookie_check' => $_POST['preflight_cookie_check'] ?? 'off',
        'required_headers_check' => $_POST['required_headers_check'] ?? 'off',
        'accept_language_keywords_check' => $_POST['accept_language_keywords_check'] ?? 'off',
        'accept_language_required_keywords' => $_POST['accept_language_required_keywords'] ?? 'pt-BR,pt',
        'device_memory_header_max_check' => $_POST['device_memory_header_max_check'] ?? 'off',
        'device_memory_header_block_min' => $_POST['device_memory_header_block_min'] ?? '16',
        'device_memory_js_max_check' => $_POST['device_memory_js_max_check'] ?? 'off',
        'device_memory_js_block_min' => $_POST['device_memory_js_block_min'] ?? '16',
        'client_min_score' => $_POST['client_min_score'] ?? '70',
        'client_check_delay' => $_POST['client_check_delay'] ?? '1500',
        'behavior_ban_minutes' => $_POST['behavior_ban_minutes'] ?? '1440',
        'honeypot' => $_POST['honeypot'] ?? 'off',
        'resource_check' => $_POST['resource_check'] ?? 'off',
        'pow_check' => $_POST['pow_check'] ?? 'off',
        'motion_check' => $_POST['motion_check'] ?? 'off',
        'gpu_check' => $_POST['gpu_check'] ?? 'off',
        'vibration_check' => $_POST['vibration_check'] ?? 'off',
        'action_timing' => $_POST['action_timing'] ?? 'off',
        'min_action_ms' => $_POST['min_action_ms'] ?? '500',
        'render_viewport_activity_check' => $_POST['render_viewport_activity_check'] ?? 'off',
        'min_render_viewport_activity_total' => $_POST['min_render_viewport_activity_total'] ?? '1',
        'min_render_resize_event_count' => $_POST['min_render_resize_event_count'] ?? '0',
        'min_render_visual_resize_event_count' => $_POST['min_render_visual_resize_event_count'] ?? '0',
        'min_render_visual_scroll_event_count' => $_POST['min_render_visual_scroll_event_count'] ?? '0',
        'render_focus_event_check' => $_POST['render_focus_event_check'] ?? 'off',
        'render_synthetic_click_ms_check' => $_POST['render_synthetic_click_ms_check'] ?? 'off',
        'min_render_synthetic_click_ms' => $_POST['min_render_synthetic_click_ms'] ?? '1',
        'max_render_synthetic_click_ms' => $_POST['max_render_synthetic_click_ms'] ?? '3000',
        'render_service_worker_ready_check' => $_POST['render_service_worker_ready_check'] ?? 'off',
        'render_service_worker_ready_expected' => $_POST['render_service_worker_ready_expected'] ?? 'true',
        'render_web_share_supported_check' => $_POST['render_web_share_supported_check'] ?? 'off',
        'render_web_share_supported_expected' => $_POST['render_web_share_supported_expected'] ?? 'true',
        'render_payment_wallet_check' => $_POST['render_payment_wallet_check'] ?? 'off',
        'payment_request_block_error_keywords' => $_POST['payment_request_block_error_keywords'] ?? 'UnknownError',
        'render_media_capabilities_power_efficient_check' => $_POST['render_media_capabilities_power_efficient_check'] ?? 'off',
        'media_capabilities_power_efficient_false_min' => $_POST['media_capabilities_power_efficient_false_min'] ?? '1',
        'headless_extra_check' => $_POST['headless_extra_check'] ?? 'off',
        'client_hints_check' => $_POST['client_hints_check'] ?? 'off',
        'cookie_check' => $_POST['cookie_check'] ?? 'off',
        'pixel_ratio_check' => $_POST['pixel_ratio_check'] ?? 'off',
        'mobile_fonts_check' => $_POST['mobile_fonts_check'] ?? 'off',
        'timezone_check' => $_POST['timezone_check'] ?? 'off',
        'expected_timezones' => $_POST['expected_timezones'] ?? '',
        'network_check' => $_POST['network_check'] ?? 'off',
        'battery_check' => $_POST['battery_check'] ?? 'off',
        'device_memory_check' => $_POST['device_memory_check'] ?? 'off',
        'audio_fingerprint_check' => $_POST['audio_fingerprint_check'] ?? 'off',
        'storage_check' => $_POST['storage_check'] ?? 'off',
        'pointer_check' => $_POST['pointer_check'] ?? 'off',
        'local_debug_ports_check' => $_POST['local_debug_ports_check'] ?? 'off',
        'whatsapp_deep_link_check' => $_POST['whatsapp_deep_link_check'] ?? 'off',
        'auto_bot_signatures' => $_POST['auto_bot_signatures'] ?? 'off',
        'bot_signatures' => $_POST['bot_signatures'] ?? '',
        'auto_datacenter' => $_POST['auto_datacenter'] ?? 'off',
        'datacenter_keywords' => $_POST['datacenter_keywords'] ?? '',
        'ja3_hashes' => $_POST['ja3_hashes'] ?? ''
    ];
    file_put_contents($arquivoConfig, json_encode($novaConfig, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    header("Location: dashboard.php?salvo=1");
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'clear_logs') {
    file_put_contents($arquivoLog, json_encode([]));
    header('Location: ' . strtok($_SERVER['REQUEST_URI'] ?? 'dashboard.php', '?'));
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'clear_marks') {
    file_put_contents($arquivoMarcas, json_encode([]));
    header('Location: ' . strtok($_SERVER['REQUEST_URI'] ?? 'dashboard.php', '?'));
    exit;
}

$acessos = readJsonFile($arquivoLog, []);
$marcados = readJsonFile($arquivoMarcas, []);
$config = $defaults;
$tempConfig = readJsonFile($arquivoConfig, []);
if (is_array($tempConfig)) $config = array_merge($defaults, $tempConfig);
?>
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TrafficGuard | Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <style>
        body { background-color: #f4f6f9; font-size: 0.85rem; }
        .nav-tabs .nav-link.active { font-weight: bold; border-top: 3px solid #0d6efd; }
        .card { border:none; box-shadow: 0 2px 5px rgba(0,0,0,0.05); border-radius: 8px; }
        .table thead th { background-color: #212529; color: #fff; font-size: 0.75rem; text-transform: uppercase; padding: 10px; }
        .table td { vertical-align: middle; padding: 8px 10px; border-bottom: 1px solid #eee; }
        .ua-cell { font-family: monospace; font-size: 0.7rem; color: #555; min-width: 200px; max-width: 400px; word-wrap: break-word; white-space: normal; line-height: 1.2; }
        .badge-reason { font-size: 0.65rem; text-transform: uppercase; white-space: normal; text-align: left; line-height: 1.25; }
        label { font-weight: 600; margin-bottom: 5px; color: #495057; }
        .form-control, .form-select { font-size: 0.9rem; }
        .help-text { font-size: 0.75rem; color: #777; margin-bottom: 10px; display: block; }
        .filter-btn { min-width: 100px; font-weight: 500; font-size: 0.8rem; }
        .filter-active { background-color: #0d6efd !important; color: white !important; border-color: #0d6efd !important; }
        .form-switch .form-check-input { width: 3em; height: 1.5em; cursor: pointer; }
        .switch-row { min-height: 50px; border-bottom: 1px solid #edf0f3; }
        .switch-row:last-child { border-bottom: 0; }
        .metric { min-width: 110px; }
        .access-row { cursor: default; }
        .access-row:focus { outline: 2px solid #0d6efd; outline-offset: -2px; }
        .row-pending td { background-color: #fff8df; }
        .detail-label { color: #6c757d; font-size: 0.7rem; text-transform: uppercase; font-weight: 700; }
        .detail-value { font-size: 0.85rem; overflow-wrap: anywhere; }
        .detail-json { background: #111827; color: #e5e7eb; border-radius: 6px; padding: 14px; max-height: 320px; overflow: auto; font-size: 0.72rem; white-space: pre-wrap; }
        .check-observed { max-width: 420px; overflow-wrap: anywhere; white-space: normal; }
        .details-icon-btn { width: 32px; height: 32px; display: inline-grid; place-items: center; padding: 0; }
        .details-icon-btn i { font-size: 1rem; line-height: 1; }
        .details-column { width: 48px; min-width: 48px; text-align: center; }
        .detail-header { background: #fff; border-bottom: 1px solid #dee2e6; padding: 18px 0; margin-bottom: 20px; }
        .detail-summary { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); border: 1px solid #dee2e6; background: #fff; margin-bottom: 22px; }
        .detail-summary-item { padding: 14px 16px; border-right: 1px solid #dee2e6; min-width: 0; }
        .detail-summary-item:last-child { border-right: 0; }
        .detail-section { background: #fff; border-top: 3px solid #212529; margin-bottom: 22px; }
        .detail-section-header { padding: 14px 16px; border-bottom: 1px solid #dee2e6; }
        .detail-section-body { padding: 16px; }
        .detail-data-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); border: 1px solid #e5e7eb; }
        .detail-data-item { padding: 12px 14px; border-right: 1px solid #e5e7eb; border-bottom: 1px solid #e5e7eb; min-width: 0; }
        .detail-data-item:nth-child(3n) { border-right: 0; }
        @media (max-width: 991px) {
            .detail-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
            .detail-summary-item:nth-child(2) { border-right: 0; }
            .detail-data-grid { grid-template-columns: 1fr; }
            .detail-data-item, .detail-data-item:nth-child(3n) { border-right: 0; }
        }
    </style>
</head>
<body>

<div class="container-fluid p-4">
    <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-4">
        <h4 class="fw-bold text-primary m-0">TrafficGuard <span class="text-muted fw-normal">| Dashboard</span></h4>
        <div class="d-flex flex-wrap gap-2">
            <span class="badge bg-secondary d-flex align-items-center metric"><?php echo count($acessos); ?> Cliques</span>
            <span class="badge bg-dark d-flex align-items-center metric">Blacklist comport. pausada</span>
            <button onclick="window.location.reload()" class="btn btn-primary btn-sm">Refresh</button>
            <form method="post" class="m-0" onsubmit="return confirm('Limpar IPs marcados por comportamento?');"><input type="hidden" name="action" value="clear_marks"><input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>"><button class="btn btn-outline-dark btn-sm" type="submit">LIMPAR MARCADOS</button></form>
            <form method="post" class="m-0" onsubmit="return confirm('Apagar historico?');"><input type="hidden" name="action" value="clear_logs"><input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>"><button class="btn btn-danger btn-sm" type="submit">LIMPAR LOGS</button></form>
            <form method="post" class="m-0"><input type="hidden" name="action" value="logout"><input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>"><button class="btn btn-outline-secondary btn-sm" type="submit">SAIR</button></form>
        </div>
    </div>

    <?php if (isset($_GET['salvo'])): ?>
        <div class="alert alert-success py-2">Configuracoes salvas.</div>
    <?php endif; ?>

    <ul class="nav nav-tabs mb-3" id="myTab" role="tablist">
        <li class="nav-item" role="presentation">
            <button class="nav-link active" id="home-tab" data-bs-toggle="tab" data-bs-target="#home" type="button" role="tab">Monitor de Trafego</button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="config-tab" data-bs-toggle="tab" data-bs-target="#config" type="button" role="tab">Configuracoes & Filtros</button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="details-tab" data-bs-toggle="tab" data-bs-target="#details" type="button" role="tab">Detalhes do acesso</button>
        </li>
    </ul>

    <div class="tab-content" id="myTabContent">
        <div class="tab-pane fade show active" id="home" role="tabpanel">
            <div class="d-flex flex-wrap gap-2 mb-3">
                <button class="btn btn-outline-secondary filter-btn filter-active" onclick="filterTable('all', this)">Todos</button>
                <button class="btn btn-outline-success filter-btn" onclick="filterTable('allowed', this)">Permitidos</button>
                <button class="btn btn-outline-danger filter-btn" onclick="filterTable('blocked', this)">Bloqueados</button>
                <button class="btn btn-outline-warning filter-btn" onclick="filterTable('pending', this)">Pendentes</button>
            </div>

            <div class="card p-0">
                <div class="table-responsive">
                    <table class="table table-hover mb-0" id="accessTable">
                        <thead>
                            <tr>
                                <th class="details-column" aria-label="Detalhes"></th>
                                <th>Row</th>
                                <th>IP</th>
                                <th>Country</th>
                                <th>ISP</th>
                                <th>Referer</th>
                                <th>Time</th>
                                <th>Reason</th>
                                <th>OS</th>
                                <th>Query</th>
                                <th>UA (User Agent)</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($acessos)): ?>
                                <tr><td colspan="11" class="text-center p-5">Nenhum dado.</td></tr>
                            <?php else: ?>
                                <?php foreach ($acessos as $accessIndex => $v): ?>
                                    <?php
                                        $reason = $v['reason'] ?? '';
                                        $isBlocked = strpos($reason, 'BLOCKED') !== false;
                                        $isPending = strpos($reason, 'PENDING') !== false;
                                        $rowClass = $isBlocked ? 'row-blocked' : ($isPending ? 'row-pending' : 'row-allowed');
                                        $preCountry = (($v['country'] ?? '') !== 'WaitJS' && ($v['country'] ?? '') !== 'Loading...') ? ($v['country'] ?? '') : '';
                                        $preIsp = (($v['isp'] ?? '') !== 'WaitJS' && ($v['isp'] ?? '') !== 'Loading...') ? ($v['isp'] ?? '') : '';
                                        $ref = $v['referer'] ?? '';
                                        $refIsDirect = ($ref === 'Direto' || $ref === '');
                                        $serverData = $v['details']['server_data'] ?? [];
                                        if (!is_array($serverData)) $serverData = [];
                                        $sessionMeta = $serverData['session_metadata'] ?? [];
                                        if (!is_array($sessionMeta)) $sessionMeta = [];
                                        $historyData = $serverData['history'] ?? [];
                                        if (!is_array($historyData)) $historyData = [];
                                    ?>
                                    <tr class="<?php echo $rowClass; ?> access-row" data-access-index="<?php echo (int)$accessIndex; ?>">
                                        <td class="details-column"><button type="button" class="btn btn-sm btn-outline-primary details-icon-btn details-btn" data-access-index="<?php echo (int)$accessIndex; ?>" title="Abrir detalhes" aria-label="Abrir detalhes do acesso #<?php echo h($v['row'] ?? ''); ?>"><i class="bi bi-list-check" aria-hidden="true"></i></button></td>
                                        <td class="fw-bold text-primary">#<?php echo h($v['row'] ?? ''); ?></td>
                                        <td class="ip-target fw-bold" data-ip="<?php echo h($v['ip'] ?? ''); ?>"><?php echo h($v['ip'] ?? ''); ?></td>
                                        <td class="country-cell text-muted">
                                            <?php if($preCountry): echo h($preCountry); else: ?><span class="spinner-border spinner-border-sm text-muted" style="font-size:0.6rem"></span><?php endif; ?>
                                        </td>
                                        <td class="isp-cell text-muted">
                                            <?php if($preIsp): echo h($preIsp); else: ?>...<?php endif; ?>
                                        </td>
                                        <td>
                                            <?php if ($refIsDirect): ?>
                                                <span class="text-muted small">Direto</span>
                                            <?php else: ?>
                                                <a href="<?php echo h($ref); ?>" target="_blank" rel="noopener" title="<?php echo h($ref); ?>">Link</a>
                                            <?php endif; ?>
                                        </td>
                                        <td style="white-space:nowrap; font-size:0.75rem;"><?php echo h($v['data_hora'] ?? ''); ?></td>
                                        <td><?php renderReason($reason); ?></td>
                                        <td><span class="badge bg-light text-dark border"><?php echo h($v['os'] ?? ''); ?></span></td>
                                        <td><small><?php echo empty($v['query']) ? '-' : '?' . h($v['query']); ?></small></td>
                                        <td class="ua-cell"><?php echo h($v['ua'] ?? ''); ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="tab-pane fade" id="details" role="tabpanel" aria-labelledby="details-tab">
            <div class="detail-header">
                <div class="d-flex flex-wrap align-items-center gap-3">
                    <button type="button" class="btn btn-outline-secondary btn-sm details-back-btn" title="Voltar ao monitor" aria-label="Voltar ao monitor"><i class="bi bi-arrow-left" aria-hidden="true"></i></button>
                    <div>
                        <h5 class="fw-bold mb-1" id="accessDetailsTitle">Detalhes do acesso</h5>
                        <div class="text-muted small" id="accessDetailsSubtitle">Selecione um acesso no monitor.</div>
                    </div>
                </div>
            </div>
            <div id="accessDetailsBody">
                <div class="text-center text-muted py-5">Nenhum acesso selecionado.</div>
            </div>
        </div>

        <div class="tab-pane fade" id="config" role="tabpanel">
            <div class="card p-4">
                <form method="POST">
                    <input type="hidden" name="action" value="save_config">
                    <input type="hidden" name="csrf_token" value="<?php echo h($csrfToken); ?>">

                    <div class="row">
                        <div class="col-lg-6 border-end pe-lg-4">
                            <h5 class="text-danger mb-3 border-bottom pb-2">Blacklists</h5>

                            <div class="mb-3">
                                <label>IPs</label>
                                <textarea name="ips" class="form-control form-control-sm" rows="2" placeholder="Ex: 177.10.20.30"><?php echo h($config['ips']); ?></textarea>
                            </div>
                            <div class="mb-3">
                                <label>User Agents</label>
                                <textarea name="ua_keywords" class="form-control form-control-sm" rows="2" placeholder="Ex: facebook, googlebot"><?php echo h($config['ua_keywords']); ?></textarea>
                            </div>
                            <div class="mb-3">
                                <label>Paises (sigla, ex: RU, CN)</label>
                                <textarea name="countries" class="form-control form-control-sm" rows="2"><?php echo h($config['countries']); ?></textarea>
                            </div>
                            <div class="mb-3">
                                <label>ISP / Provedor</label>
                                <textarea name="isps" class="form-control form-control-sm" rows="2" placeholder="Ex: Amazon, Google Cloud"><?php echo h($config['isps']); ?></textarea>
                            </div>
                            <div class="mb-3">
                                <label>Parametros/Query</label>
                                <textarea name="queries" class="form-control form-control-sm" rows="2" placeholder="Ex: utm_source=automation-test"><?php echo h($config['queries']); ?></textarea>
                            </div>
                            <div class="mb-3">
                                <label>Referer</label>
                                <textarea name="referers" class="form-control form-control-sm" rows="2" placeholder="Ex: scanner.example"><?php echo h($config['referers']); ?></textarea>
                            </div>
                            <div class="mb-3">
                                <label>Sistema Operacional</label>
                                <textarea name="os" class="form-control form-control-sm" rows="2"><?php echo h($config['os']); ?></textarea>
                            </div>
                            <div class="mt-4 pt-3 border-top d-flex justify-content-between align-items-center form-check form-switch p-0">
                                <div class="ms-0">
                                    <label class="form-check-label fw-bold text-danger mb-0" for="lockdownSwitch">Modo Lockdown</label>
                                    <small class="d-block text-muted fw-normal" style="font-size: 0.75rem;">Bloqueia todo o trafego imediatamente.</small>
                                </div>
                                <input class="form-check-input ms-0" type="checkbox" id="lockdownSwitch" name="lockdown" value="on" <?php echo checkedOn($config, 'lockdown'); ?>>
                            </div>
                        </div>

                        <div class="col-lg-6 ps-lg-4">
                            <h5 class="text-success mb-3 border-bottom pb-2">Whitelists</h5>
                            <p class="help-text">Se preencher aqui, somente quem bater com a lista sera permitido.</p>

                            <div class="mb-3">
                                <label>Permitir Apenas IPs</label>
                                <textarea name="white_ips" class="form-control form-control-sm" rows="2"><?php echo h($config['white_ips']); ?></textarea>
                            </div>
                            <div class="mb-3">
                                <label>Permitir Apenas Paises</label>
                                <textarea name="white_countries" class="form-control form-control-sm" rows="2" placeholder="Ex: BR, PT"><?php echo h($config['white_countries']); ?></textarea>
                            </div>
                            <div class="mb-3">
                                <label>Permitir Apenas ISPs</label>
                                <textarea name="white_isps" class="form-control form-control-sm" rows="2" placeholder="Ex: Vivo, Claro, NET"><?php echo h($config['white_isps']); ?></textarea>
                            </div>
                            <div class="mb-3">
                                <label>Permitir Apenas Parametros/Query</label>
                                <textarea name="white_queries" class="form-control form-control-sm" rows="2" placeholder="Ex: utm_source=facebook"><?php echo h($config['white_queries']); ?></textarea>
                            </div>
                            <div class="mb-3">
                                <label>Permitir Apenas User Agents</label>
                                <textarea name="white_ua" class="form-control form-control-sm" rows="2" placeholder="Ex: Android, iPhone"><?php echo h($config['white_ua']); ?></textarea>
                            </div>
                            <div class="alert alert-secondary mb-3">
                                        <strong>Resposta a bloqueio:</strong> pagina neutra com HTTP 403. A versao publica nao redireciona visitantes nem entrega conteudo alternativo.
                                    </div>
                            </div>
                        </div>
                    </div>

                    <button type="submit" class="btn btn-primary btn-lg w-100 mt-3">Salvar Configuracoes</button>
                </form>
            </div>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
const accessSummaries = <?php echo json_encode(array_map(function ($access) {
    return [
        'row' => $access['row'] ?? 0,
        'data_hora' => $access['data_hora'] ?? '',
        'ip' => $access['ip'] ?? ''
    ];
}, array_values($acessos)), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;

function escapeHtml(value) {
    return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;');
}

function printable(value) {
    if (value === null || typeof value === 'undefined' || value === '') return '-';
    if (typeof value === 'object') return JSON.stringify(value, null, 2);
    if (typeof value === 'boolean') return value ? 'Sim' : 'Nao';
    return String(value);
}

function checkBadge(result) {
    const styles = {
        passou: 'bg-success',
        reprovou: 'bg-danger',
        inconclusivo: 'bg-warning text-dark',
        ignorado: 'bg-secondary',
        informativo: 'bg-info text-dark'
    };
    return `<span class="badge ${styles[result] || 'bg-secondary'}">${escapeHtml(result || 'desconhecido')}</span>`;
}

function detailField(label, value) {
    return `<div class="col-md-4 col-xl-3"><div class="detail-label">${escapeHtml(label)}</div><div class="detail-value">${escapeHtml(printable(value))}</div></div>`;
}

function summaryItem(label, value, tone = '') {
    return `<div class="detail-summary-item"><div class="detail-label">${escapeHtml(label)}</div><div class="detail-value fw-bold ${tone}">${escapeHtml(printable(value))}</div></div>`;
}

function dataItem(label, value) {
    return `<div class="detail-data-item"><div class="detail-label">${escapeHtml(label)}</div><div class="detail-value"><pre class="m-0 small text-wrap">${escapeHtml(printable(value))}</pre></div></div>`;
}

function dataSection(title, rows) {
    return `<section class="detail-section"><div class="detail-section-header"><h6 class="fw-bold mb-0">${escapeHtml(title)}</h6></div><div class="detail-section-body"><div class="detail-data-grid">${rows.map(row => dataItem(row[0], row[1])).join('')}</div></div></section>`;
}

function isConfiguredListCheck(check) {
    const key = String(check && check.key || '');
    return key === 'lockdown' || key.includes('_blacklist') || key.includes('_whitelist');
}

function isConfiguredListReason(reason) {
    return /LOCKDOWN|\bIP Ban\b|\bUA Ban\b|\bOS Ban\b|\bRef Ban\b|Country Ban|ISP Ban|Not Whitelisted|Not Allowed|Query Param Missing|Query\/Param Ban/i.test(String(reason || ''));
}

async function openAccessDetails(index) {
    const summary = accessSummaries[index];
    if (!summary) return;
    bootstrap.Tab.getOrCreateInstance(document.getElementById('details-tab')).show();
    document.getElementById('accessDetailsTitle').textContent = `Acesso #${summary.row || '-'}`;
    document.getElementById('accessDetailsSubtitle').textContent = `${summary.data_hora || ''} | ${summary.ip || ''}`;
    document.getElementById('accessDetailsBody').innerHTML = '<div class="text-center p-5"><div class="spinner-border text-primary" role="status"></div><div class="text-muted mt-2">Carregando detalhes...</div></div>';

    let access;
    try {
        const response = await fetch(`?access_detail=${encodeURIComponent(summary.row)}`, { cache: 'no-store' });
        if (!response.ok) throw new Error('Nao foi possivel carregar este acesso.');
        access = await response.json();
    } catch (error) {
        document.getElementById('accessDetailsBody').innerHTML = `<div class="alert alert-danger">${escapeHtml(error.message || String(error))}</div>`;
        return;
    }
    const details = access.details && typeof access.details === 'object' ? access.details : {};
    const checks = (Array.isArray(details.checks) ? details.checks : []).filter(check => !isConfiguredListCheck(check));
    const scoreText = details.score === null || typeof details.score === 'undefined'
        ? 'Nao se aplica'
        : `${details.score} / minimo ${details.threshold}`;
    const failed = (Array.isArray(details.failed_reasons) ? details.failed_reasons : []).filter(reason => !isConfiguredListReason(reason));
    const failedCount = checks.filter(check => check.result === 'reprovou').length;
    const passedCount = checks.filter(check => check.result === 'passou').length;
    const inconclusiveCount = checks.filter(check => check.result === 'inconclusivo').length;
    const isBlocked = String(access.reason || '').includes('BLOCKED');
    const isPending = String(access.reason || '').includes('PENDING');
    const decisionLabel = isBlocked ? 'Bloqueado' : (isPending ? 'Aguardando validacao' : 'Permitido');
    const decisionTone = isBlocked ? 'text-danger' : (isPending ? 'text-warning' : 'text-success');
    const client = details.client_data && typeof details.client_data === 'object' ? details.client_data : {};
    const browser = client.browser && typeof client.browser === 'object' ? client.browser : {};
    const extended = browser.extended && typeof browser.extended === 'object' ? browser.extended : {};
    const server = details.server_data && typeof details.server_data === 'object' ? details.server_data : {};
    const requestContext = server.request_context && typeof server.request_context === 'object' ? server.request_context : {};
    const standardHeaders = server.standard_headers && typeof server.standard_headers === 'object' ? server.standard_headers : {};
    const proxyHeaders = server.proxy_headers && typeof server.proxy_headers === 'object' ? server.proxy_headers : {};
    const traceHeaders = server.trace_headers && typeof server.trace_headers === 'object' ? server.trace_headers : {};
    const authorizationMetadata = server.authorization_metadata && typeof server.authorization_metadata === 'object' ? server.authorization_metadata : {};
    const cookieMetadata = server.cookie_metadata && typeof server.cookie_metadata === 'object' ? server.cookie_metadata : {};
    const payloadMetadata = server.payload_metadata && typeof server.payload_metadata === 'object' ? server.payload_metadata : {};
    const sessionMetadata = server.session_metadata && typeof server.session_metadata === 'object' ? server.session_metadata : {};
    const preflightMetadata = server.preflight_metadata && typeof server.preflight_metadata === 'object' ? server.preflight_metadata : {};
    const clientHints = server.client_hints && typeof server.client_hints === 'object' ? server.client_hints : {};
    const advancedServerMetrics = server.advanced_server_metrics && typeof server.advanced_server_metrics === 'object' ? server.advanced_server_metrics : {};
    const networkIdentity = server.network_identity && typeof server.network_identity === 'object' ? server.network_identity : {};
    const reverseDns = server.reverse_dns && typeof server.reverse_dns === 'object' ? server.reverse_dns : (networkIdentity.reverse_dns && typeof networkIdentity.reverse_dns === 'object' ? networkIdentity.reverse_dns : {});
    const flowTiming = sessionMetadata.flow_timing && typeof sessionMetadata.flow_timing === 'object' ? sessionMetadata.flow_timing : {};
    const history = server.history && typeof server.history === 'object' ? server.history : {};
    const flowHistory = history.flow_history && typeof history.flow_history === 'object' ? history.flow_history : {};
    const responseAtLog = server.response_at_log && typeof server.response_at_log === 'object' ? server.response_at_log : {};
    const decisionAtLog = server.decision_at_log && typeof server.decision_at_log === 'object' ? server.decision_at_log : {};
    const gpu = client.gpuInfo && typeof client.gpuInfo === 'object' ? client.gpuInfo : {};
    const renderSignals = client.renderSignals && typeof client.renderSignals === 'object' ? client.renderSignals : {};
    const renderGate = client.renderGate && typeof client.renderGate === 'object' ? client.renderGate : {};
    const renderRaf = renderSignals.raf && typeof renderSignals.raf === 'object' ? renderSignals.raf : {};
    const renderCss = renderSignals.css_animation && typeof renderSignals.css_animation === 'object' ? renderSignals.css_animation : {};
    const renderIntersection = renderSignals.intersection && typeof renderSignals.intersection === 'object' ? renderSignals.intersection : {};
    const renderLayoutShift = renderSignals.layout_shift && typeof renderSignals.layout_shift === 'object' ? renderSignals.layout_shift : {};
    const renderViewport = renderSignals.viewport && typeof renderSignals.viewport === 'object' ? renderSignals.viewport : {};
    const renderFonts = renderSignals.font_loading && typeof renderSignals.font_loading === 'object' ? renderSignals.font_loading : {};
    const renderMedia = renderSignals.media_queries && typeof renderSignals.media_queries === 'object' ? renderSignals.media_queries : {};
    const renderVideo = renderSignals.video_codecs && typeof renderSignals.video_codecs === 'object' ? renderSignals.video_codecs : {};
    const renderNetwork = renderSignals.network_save_data && typeof renderSignals.network_save_data === 'object' ? renderSignals.network_save_data : {};
    const renderEvents = renderSignals.user_events && typeof renderSignals.user_events === 'object' ? renderSignals.user_events : {};
    const renderExtra = renderSignals.extra_initial_signals && typeof renderSignals.extra_initial_signals === 'object' ? renderSignals.extra_initial_signals : {};
    const flowProgress = details.flow_progress && typeof details.flow_progress === 'object' ? details.flow_progress : {};
    const flowClassification = details.flow_classification && typeof details.flow_classification === 'object'
        ? details.flow_classification
        : (flowProgress.classification && typeof flowProgress.classification === 'object' ? flowProgress.classification : {});
    const postExecution = details.post_execution && typeof details.post_execution === 'object'
        ? details.post_execution
        : (flowProgress.post_execution && typeof flowProgress.post_execution === 'object' ? flowProgress.post_execution : {});
    const flowDiagnostic = details.flow_diagnostic && typeof details.flow_diagnostic === 'object' ? details.flow_diagnostic : {};
    const flowSteps = Array.isArray(flowProgress.steps) ? flowProgress.steps : [];
    const validationPostText = postExecution.validation_post_received === true ? 'Sim' : (postExecution.validation_post_received === false ? 'Nao' : 'Nao informado');
    const diagnosticPostText = postExecution.diagnostic_post_received === true ? 'Sim' : (postExecution.diagnostic_post_received === false ? 'Nao' : 'Nao informado');

    document.getElementById('accessDetailsTitle').textContent = `Acesso #${access.row || '-'}`;
    document.getElementById('accessDetailsSubtitle').textContent = `${access.data_hora || ''} | ${access.ip || ''}`;

    let html = `<div class="detail-summary">
        ${summaryItem('Decisao', decisionLabel, decisionTone)}
        ${summaryItem('Score', scoreText)}
        ${summaryItem('Testes', `${passedCount} passaram | ${failedCount} reprovaram`)}
        ${summaryItem('Inconclusivos', inconclusiveCount)}
    </div>`;

    html += dataSection('Identificacao do acesso', [
        ['IP', access.ip],
        ['Pais / ISP', `${access.country || '-'} / ${access.isp || '-'}`],
        ['Sistema', access.os],
        ['Data e hora', access.data_hora],
        ['Ultima atualizacao', access.atualizado_em],
        ['Referer', access.referer],
        ['Query', access.query],
        ['Metodo HTTP', server.request_method],
        ['Etapa final', details.stage || 'Registro antigo'],
        ['User-Agent', access.ua]
    ]);

    html += dataSection('Diagnostico de execucao do JS e POST', [
        ['Classificacao do fluxo', flowClassification.code || '-'],
        ['Leitura do diagnostico', flowClassification.label || '-'],
        ['Interpretacao provavel', flowClassification.likely || '-'],
        ['Ultimo passo registrado', flowProgress.last_step || flowClassification.last_step || '-'],
        ['POST de validacao chegou?', validationPostText],
        ['POST apenas de diagnostico chegou?', diagnosticPostText],
        ['Resumo do POST', postExecution.summary || '-'],
        ['Etapa do POST', postExecution.post_stage || '-'],
        ['Motivo tecnico', flowDiagnostic.motivo_tecnico || flowDiagnostic.error || '-'],
        ['Stage reportado pelo navegador', flowDiagnostic.reported_stage || '-'],
        ['Quantidade de etapas registradas', flowSteps.length],
        ['Sequencia de etapas', flowSteps.map(step => ({ step: step.step, at: step.at_iso, original: step.nome_original || step.nome_original_proximo || '', atual: step.nome_atual || step.nome_atual_proximo || '', browser: step.browser || null, transport: step.transport || null, compile: step.compile || null, source: step.source || null }))]
    ]);

    if (!checks.length) {
        html += '<div class="alert alert-secondary">Este acesso foi registrado antes da coleta detalhada. Os novos acessos mostrarao todos os testes e valores recebidos.</div>';
    } else {
        html += `<section class="detail-section"><div class="detail-section-header d-flex flex-wrap justify-content-between align-items-center gap-2">
            <h6 class="fw-bold mb-0">Sequencia das defesas automaticas</h6>
            <small class="text-muted">Filtros configuraveis de blacklist e whitelist foram omitidos.</small>
        </div><div class="table-responsive"><table class="table table-sm table-hover align-middle mb-0">
            <thead><tr><th>#</th><th>Teste</th><th>Resultado</th><th>Pontos</th><th>Dado recebido</th><th>Esperado</th></tr></thead><tbody>`;
        checks.forEach((check, checkIndex) => {
            const points = Number(check.points || 0);
            const pointsClass = points > 0 ? 'text-success' : (points < 0 ? 'text-danger' : 'text-muted');
            html += `<tr>
                <td>${checkIndex + 1}</td>
                <td><strong>${escapeHtml(check.label || check.key || '-')}</strong><div class="text-muted small">${escapeHtml(check.key || '')}</div></td>
                <td>${checkBadge(check.result)}</td>
                <td class="fw-bold ${pointsClass}">${points > 0 ? '+' : ''}${points}</td>
                <td class="check-observed"><pre class="m-0 small text-wrap">${escapeHtml(printable(check.observed))}</pre></td>
                <td class="check-observed"><pre class="m-0 small text-wrap">${escapeHtml(printable(check.expected))}</pre></td>
            </tr>`;
        });
        html += '</tbody></table></div></section>';
    }

    if (failed.length) {
        html += `<section class="detail-section"><div class="detail-section-header"><h6 class="fw-bold mb-0 text-danger">Sinais acionados</h6></div><div class="detail-section-body"><div class="alert alert-danger mb-0 py-2">${failed.map(item => `<div>${escapeHtml(item)}</div>`).join('')}</div></div></section>`;
    }

    html += dataSection('Render Signals - etapa inicial do loading', [
        ['Gate de renderizacao', renderGate],
        ['Tempo total da coleta', renderSignals.total_elapsed_ms ? `${renderSignals.total_elapsed_ms} ms` : '-'],
        ['requestAnimationFrame', renderRaf],
        ['CSS animation / transition', renderCss],
        ['IntersectionObserver', renderIntersection],
        ['Layout Shift / PerformanceObserver', renderLayoutShift],
        ['Viewport / resize / scroll', renderViewport],
        ['DPR e media queries', renderMedia],
        ['document.fonts.ready', renderFonts],
        ['HTML5 video canPlayType', renderVideo],
        ['SaveData / conexao', renderNetwork],
        ['Eventos naturais', renderEvents],
        ['Sinais extras das imagens', renderExtra]
    ]);

    html += dataSection('Render Signals extras - etapa inicial', [
        ['Foco em elemento nao-input', renderExtra.non_input_focus],
        ['Media Query Listener / orientacao', renderExtra.media_query_listener],
        ['Fontes do sistema por DOM', renderExtra.system_font_dom],
        ['Credential hints / autocomplete', renderExtra.credential_hints],
        ['Permissions API sem prompt', renderExtra.permissions_state],
        ['Spellcheck / contenteditable', renderExtra.spellcheck],
        ['SharedArrayBuffer / isolamento', renderExtra.shared_array_buffer],
        ['AudioContext/OfflineAudio informativo', renderExtra.audio_context_latency],
        ['Canvas texto leve', renderExtra.canvas_text_render],
        ['Iframe same-origin', renderExtra.same_origin_iframe],
        ['Service Worker lifecycle lab', renderExtra.service_worker_lifecycle],
        ['Web Share API', renderExtra.web_share_support],
        ['Payment Request / carteiras', renderExtra.payment_request_capabilities],
        ['MediaCapabilities decodingInfo', renderExtra.media_capabilities_decoding],
        ['WebRTC / ICE raw lab V36', renderExtra.rtc_candidate_state || renderExtra.webrtc_ice_state],
        ['Scroll/anchor/layout micro', renderExtra.scroll_and_layout_micro],
        ['Clique sintetico em estado ativo', renderExtra.synthetic_active_state],
        ['Notas', renderExtra.notes]
    ]);

    html += dataSection('Navegador e plataforma', [
        ['User-Agent do JavaScript', client.clientUserAgent || browser.userAgent],
        ['Plataforma', client.platform || browser.platform],
        ['Fornecedor', browser.vendor],
        ['Idioma', browser.language],
        ['Idiomas', browser.languages],
        ['Cookies habilitados', browser.cookieEnabled],
        ['WebDriver', client.webdriver],
        ['Client Hints completos', extended.userAgentData || browser.userAgentData],
        ['Plugins', extended.plugins],
        ['MIME types', extended.mimeTypes]
    ]);

    html += dataSection('Tela, hardware e GPU', [
        ['Tela', browser.screen],
        ['Viewport interno', browser.viewport],
        ['Viewport externo', browser.outerViewport],
        ['Orientacao', browser.orientation],
        ['Device Pixel Ratio', client.devicePixelRatio || browser.devicePixelRatio],
        ['Pontos de toque', client.touchPoints],
        ['CPU threads', browser.hardwareConcurrency],
        ['Memoria aproximada', client.deviceMemoryValue],
        ['GPU vendor', gpu.vendor],
        ['GPU renderer', gpu.renderer],
        ['Extensoes mobile', gpu.extensions],
        ['Canvas fingerprint', client.canvasFingerprint]
    ]);

    html += dataSection('Rede, armazenamento e capacidades', [
        ['Fuso horario', client.timezone || browser.timezone],
        ['Offset do fuso', browser.timezoneOffset],
        ['Conexao', browser.connection],
        ['LocalStorage', client.localStorageAvailable],
        ['SessionStorage', client.sessionStorageAvailable],
        ['Estimativa de armazenamento', extended.storageEstimate],
        ['Permissoes', extended.permissions],
        ['Dispositivos de midia', extended.mediaDevices],
        ['Capacidades', extended.capabilities],
        ['CSS media features', extended.cssMediaFeatures],
        ['Memoria de desempenho', extended.performanceMemory],
        ['Detalhes do navegador', extended.navigatorDetails],
        ['Estado do documento', extended.documentDetails],
        ['Recursos da janela', extended.windowFeatures],
        ['Audio fingerprint', client.audioFingerprintInfo || client.audioFingerprint],
        ['Bateria', { available: client.batteryAvailable, level: client.batteryLevel, charging: client.batteryCharging }]
    ]);

    html += dataSection('Sensores e interacao', [
        ['API de movimento', client.motionApiAvailable],
        ['Permissao de movimento', client.motionPermissionState],
        ['Eventos do acelerometro', client.motionEventCount],
        ['Movimentos detectados', client.movementCount],
        ['Ultima amostra', client.motionSample],
        ['API de vibracao', client.vibrateSupported],
        ['Portas locais de debug', client.localDebugPorts],
        ['Deep link do WhatsApp', client.whatsAppDeepLink],
        ['Primeira interacao', client.firstActionMs],
        ['Touch perfeito', client.perfectTouch],
        ['Wheel em mobile', client.wheelOnMobile],
        ['Pixel carregado', client.pixelLoaded],
        ['Erro no pixel', client.pixelError]
    ]);

    html += dataSection('Requisicao observada pelo servidor', [
        ['IP', server.ip],
        ['Pais / ISP', `${server.country || '-'} / ${server.isp || '-'}`],
        ['URI completa', requestContext.request_uri],
        ['Caminho', requestContext.path],
        ['Metodo', server.request_method],
        ['Protocolo HTTP', requestContext.protocol],
        ['Esquema', requestContext.scheme],
        ['Host', server.host],
        ['Porta remota', requestContext.remote_port],
        ['Porta do servidor', requestContext.server_port],
        ['Endereco do servidor', requestContext.server_address],
        ['Nome do servidor', requestContext.server_name],
        ['Horario ISO', requestContext.request_time_iso8601],
        ['Processamento ate o log (ms)', requestContext.processing_ms_at_log],
        ['Acao interna', requestContext.action],
        ['Identificador da pagina', requestContext.page_id],
        ['Quantidade de headers', requestContext.header_count],
        ['Nomes dos headers', requestContext.header_names]
    ]);

    html += dataSection('Headers HTTP recebidos', [
        ['Accept', server.accept],
        ['Content-Type', server.content_type],
        ['Content-Length', standardHeaders.content_length],
        ['Accept-Language', server.accept_language],
        ['Accept-Encoding', server.accept_encoding],
        ['Origin', standardHeaders.origin],
        ['Connection', standardHeaders.connection],
        ['Cache-Control', standardHeaders.cache_control],
        ['Pragma', standardHeaders.pragma],
        ['Upgrade-Insecure-Requests', standardHeaders.upgrade_insecure_requests],
        ['DNT', standardHeaders.dnt],
        ['Sec-GPC', standardHeaders.sec_gpc],
        ['Sec-Fetch-User', standardHeaders.sec_fetch_user],
        ['Priority', standardHeaders.priority],
        ['Range', standardHeaders.range],
        ['If-Range', standardHeaders.if_range],
        ['If-None-Match', standardHeaders.if_none_match],
        ['If-Modified-Since', standardHeaders.if_modified_since],
        ['If-Match', standardHeaders.if_match],
        ['If-Unmodified-Since', standardHeaders.if_unmodified_since],
        ['TE', standardHeaders.te],
        ['Via', standardHeaders.via],
        ['Sec-CH-UA', server.sec_ch_ua],
        ['Sec-CH-UA-Mobile', server.sec_ch_ua_mobile],
        ['Sec-CH-UA-Platform', server.sec_ch_ua_platform],
        ['Sec-Fetch-Site', server.sec_fetch_site],
        ['Sec-Fetch-Mode', server.sec_fetch_mode],
        ['Sec-Fetch-Dest', server.sec_fetch_dest],
        ['JA3', server.ja3]
    ]);

    html += dataSection('Proxy, CDN e rastreamento tecnico', [
        ['Forwarded', proxyHeaders.forwarded],
        ['X-Forwarded-For', proxyHeaders.x_forwarded_for],
        ['Cadeia de IPs encaminhados', proxyHeaders.x_forwarded_for_chain],
        ['Quantidade de proxies declarados', proxyHeaders.x_forwarded_for_count],
        ['X-Forwarded-Proto', proxyHeaders.x_forwarded_proto],
        ['X-Forwarded-Host', proxyHeaders.x_forwarded_host],
        ['X-Forwarded-Port', proxyHeaders.x_forwarded_port],
        ['X-Real-IP', proxyHeaders.x_real_ip],
        ['CF-Connecting-IP', proxyHeaders.cf_connecting_ip],
        ['CDN-Loop', proxyHeaders.cdn_loop],
        ['X-Request-ID', traceHeaders.x_request_id],
        ['Traceparent', traceHeaders.traceparent],
        ['Tracestate', traceHeaders.tracestate],
        ['Baggage', traceHeaders.baggage]
    ]);

    html += dataSection('Sessao, cookies, autorizacao e payload', [
        ['Autorizacao', authorizationMetadata],
        ['Cookies (sem valores)', cookieMetadata],
        ['Sessao anonimizada', sessionMetadata],
        ['Pre-validacao e tempos', preflightMetadata],
        ['Payload (sem conteudo)', payloadMetadata],
        ['Cookie do gate recebido', server.gate_cookie_received],
        ['Cookie HTTP da pre-validacao', server.preflight_http_cookie_received],
        ['Cookie JavaScript da pre-validacao', server.preflight_js_cookie_received]
    ]);

    html += dataSection('Client Hints opcionais recebidos pelo PHP', [
        ['Versao completa', clientHints.sec_ch_ua_full_version],
        ['Lista de versoes', clientHints.sec_ch_ua_full_version_list],
        ['Versao da plataforma', clientHints.sec_ch_ua_platform_version],
        ['Arquitetura', clientHints.sec_ch_ua_arch],
        ['Quantidade de bits', clientHints.sec_ch_ua_bitness],
        ['WoW64', clientHints.sec_ch_ua_wow64],
        ['Modelo', clientHints.sec_ch_ua_model],
        ['Formato do dispositivo', clientHints.sec_ch_ua_form_factors],
        ['Device-Memory', clientHints.device_memory],
        ['Sec-CH-Device-Memory', clientHints.sec_ch_device_memory],
        ['Memoria efetiva usada', clientHints.device_memory_details],
        ['DPR', clientHints.dpr],
        ['Width', clientHints.width],
        ['Viewport-Width', clientHints.viewport_width],
        ['Save-Data', clientHints.save_data],
        ['ECT', clientHints.ect],
        ['RTT', clientHints.rtt],
        ['Downlink', clientHints.downlink]
    ]);

    html += dataSection('Historico calculado no servidor', [
        ['Acessos anteriores do mesmo IP', history.previous_same_ip_total],
        ['Acessos anteriores da mesma sessao', history.previous_same_session_total],
        ['Bloqueios anteriores do IP', history.previous_blocks_same_ip],
        ['Pendencias anteriores do IP', history.previous_pending_same_ip],
        ['Permitidos anteriores do IP', history.previous_allowed_same_ip],
        ['Gates anteriores nao concluidos', history.previous_unfinished_gates_same_ip],
        ['Requisicoes em 60 segundos', history.requests_same_ip_last_60_seconds],
        ['Requisicoes em 5 minutos', history.requests_same_ip_last_5_minutes],
        ['Requisicoes em 1 hora', history.requests_same_ip_last_hour],
        ['Requisicoes dentro de 1 segundo', history.requests_same_ip_within_one_second],
        ['Segundos desde o acesso anterior', history.seconds_since_previous_same_ip],
        ['User-Agents diferentes no IP', history.unique_user_agents_same_ip],
        ['Paises diferentes no IP', history.unique_countries_same_ip],
        ['ISPs diferentes no IP', history.unique_isps_same_ip],
        ['IPs diferentes na sessao', history.unique_ips_same_session],
        ['Sessoes diferentes no IP', history.unique_sessions_same_ip],
        ['User-Agent mudou', history.user_agent_changed_for_ip],
        ['Pais mudou', history.country_changed_for_ip],
        ['ISP mudou', history.isp_changed_for_ip],
        ['Metodo HTTP incomum', history.unusual_http_method],
        ['Caminho sensivel', history.sensitive_path_pattern],
        ['Somente informativo', history.informational_only]
    ]);

    html += dataSection('Contagem de metodos HTTP', [
        ['Metodo atual', history.current_request_method_bucket || sessionMetadata.current_method_bucket || server.request_method],
        ['Sessao atual: GET', sessionMetadata.get_count],
        ['Sessao atual: POST', sessionMetadata.post_count],
        ['Sessao atual: HEAD', sessionMetadata.head_count],
        ['Sessao atual: outros', sessionMetadata.other_method_count],
        ['Sessao atual: mapa completo', sessionMetadata.method_counts],
        ['Mesmo IP: metodos anteriores', history.method_counts_same_ip],
        ['Mesmo IP: metodos incluindo atual', history.method_counts_same_ip_including_current],
        ['Mesma sessao: metodos anteriores', history.method_counts_same_session],
        ['Mesma sessao: metodos incluindo atual', history.method_counts_same_session_including_current],
        ['Mesmo IP nos ultimos 60 segundos', history.method_counts_same_ip_last_60_seconds],
        ['Mesmo IP nos ultimos 5 minutos', history.method_counts_same_ip_last_5_minutes],
        ['Mesmo IP na ultima hora', history.method_counts_same_ip_last_hour],
        ['POST sem GET anterior na mesma sessao', history.post_without_prior_get_same_session],
        ['Status informativo do POST', sessionMetadata.post_status]
    ]);

    html += dataSection('Fluxo GET -> GET -> POST', [
        ['Primeiro GET', { at: flowTiming.first_get_unix, kind: flowTiming.first_get_kind }],
        ['Segundo GET', { at: flowTiming.second_get_unix, kind: flowTiming.second_get_kind }],
        ['POST client_check', flowTiming.client_check_post_unix],
        ['GET1 -> GET2 (ms)', flowTiming.get1_to_get2_ms],
        ['GET2 -> POST (ms)', flowTiming.get2_to_post_ms],
        ['GET1 -> POST (ms)', flowTiming.get1_to_post_ms],
        ['Delay esperado do client_check (ms)', flowTiming.expected_client_delay_ms],
        ['POST depois do delay esperado (ms)', flowTiming.post_after_expected_delay_ms],
        ['POST mais rapido que esperado por 250ms', flowTiming.post_faster_than_expected_by_250ms],
        ['POST quase cravado no delay esperado', flowTiming.post_near_exact_expected_delay_50ms],
        ['Contagem bruta/interna/comportamental', { raw: flowTiming.raw_request_count, internal: flowTiming.internal_request_count, behavioral: flowTiming.behavioral_request_count }],
        ['GET/POST brutos', { get: flowTiming.raw_get_count, post: flowTiming.raw_post_count }],
        ['GET/POST comportamentais', { get: flowTiming.behavioral_get_count, post: flowTiming.behavioral_post_count }],
        ['Timing bruto do fluxo', flowTiming.raw_timing],
        ['Timing comportamental do fluxo', flowTiming.behavioral_timing],
        ['Sequencia do fluxo na sessao', flowTiming.sequence],
        ['Historico do mesmo flow no log', flowHistory],
        ['Observacao', flowTiming.note]
    ]);

    html += dataSection('Entropia de tempo e cadencia mecanica', [
        ['Variancia da sessao (tracker exemplo)', sessionMetadata.timing_variance],
        ['Media dos intervalos da sessao (s)', sessionMetadata.timing_mean_interval_seconds],
        ['Intervalos usados na sessao (s)', sessionMetadata.timing_interval_sample_seconds],
        ['Tamanho da amostra da sessao', sessionMetadata.timing_sample_size],
        ['Cadencia mecanica suspeita pela variancia', sessionMetadata.mechanical_timing_suspected],
        ['Regra da variancia', sessionMetadata.mechanical_timing_rule],
        ['Entropia por historico IP+sessao', history.time_cadence_entropy]
    ]);

    html += dataSection('Reuso de User-Agent, payload e formato', [
        ['Reuso do mesmo User-Agent', history.same_user_agent_reuse],
        ['Reuso de body/hash e formato da requisicao', history.payload_reuse],
        ['Taxas comportamentais do mesmo IP', history.behavior_rates_same_ip],
        ['Rotas sensiveis', history.sensitive_paths]
    ]);

    html += dataSection('Sequencia recente observada', [
        ['Sequencia recente de caminhos', history.recent_path_sequence],
        ['Sequencia metodo + caminho + acao', history.recent_method_path_sequence]
    ]);

    html += dataSection('ASN, rede e identidade do IP', [
        ['ASN', networkIdentity.asn],
        ['Organizacao do ASN', networkIdentity.org],
        ['Dominio da rede', networkIdentity.domain],
        ['ISP', networkIdentity.isp],
        ['Pais', networkIdentity.country],
        ['Timezone da API de IP', networkIdentity.timezone_id],
        ['UTC da API de IP', networkIdentity.timezone_utc],
        ['Sinais de seguranca da API', networkIdentity.security],
        ['Fonte da consulta', networkIdentity.lookup_source],
        ['Consulta bem-sucedida', networkIdentity.lookup_success]
    ]);

    html += dataSection('Reverse DNS completo', [
        ['Consulta tentada', reverseDns.lookup_attempted],
        ['Veio do cache', reverseDns.cache_hit],
        ['Tempo da consulta (ms)', reverseDns.lookup_ms],
        ['PTR hostname', reverseDns.ptr_hostname],
        ['PTR disponivel', reverseDns.ptr_available],
        ['Dominio extraido do PTR', reverseDns.ptr_domain],
        ['Categoria do PTR', reverseDns.ptr_category],
        ['PTR parece hosting/datacenter', reverseDns.ptr_looks_hosting],
        ['PTR parece residencial', reverseDns.ptr_looks_residential],
        ['PTR parece mobile', reverseDns.ptr_looks_mobile],
        ['PTR parece crawler', reverseDns.ptr_looks_crawler],
        ['Bot declarado no User-Agent', reverseDns.claimed_bot_type],
        ['PTR valido para bot declarado', reverseDns.claimed_bot_ptr_valid],
        ['Dominios esperados para bot declarado', reverseDns.claimed_bot_ptr_expected_domains],
        ['Motivo para pular consulta', reverseDns.lookup_skipped_reason],
        ['TTL do cache (s)', reverseDns.cache_ttl_seconds],
        ['Observacao', reverseDns.privacy_note],
        ['Objeto completo', reverseDns]
    ]);

    html += dataSection('Metricas server-side avancadas quando disponiveis', [
        ['Reverse DNS', advancedServerMetrics.reverse_dns],
        ['Falso buscador', advancedServerMetrics.is_fake_bot],
        ['Rota blackhole', advancedServerMetrics.is_blackhole_route],
        ['HTTP/1.0 com Accept generico', advancedServerMetrics.http_1_0_generic_accept],
        ['Identidade de rede', networkIdentity],
        ['Objeto completo', advancedServerMetrics]
    ]);

    html += dataSection('Resposta no instante do registro', [
        ['Decisao registrada', decisionAtLog],
        ['Status HTTP', responseAtLog.status_at_log],
        ['Content-Type', responseAtLog.content_type_at_log],
        ['Headers definidos', responseAtLog.header_names_at_log],
        ['Location presente', responseAtLog.location_header_present_at_log],
        ['Bytes no buffer', responseAtLog.buffered_bytes_at_log],
        ['Observacao', responseAtLog.note]
    ]);

    html += `<section class="detail-section"><div class="detail-section-header"><h6 class="fw-bold mb-0">Dados brutos para auditoria</h6></div><div class="detail-section-body"><div class="row g-3"><div class="col-lg-6"><div class="detail-label mb-2">Navegador</div><pre class="detail-json">${escapeHtml(JSON.stringify(client, null, 2))}</pre></div><div class="col-lg-6"><div class="detail-label mb-2">Servidor</div><pre class="detail-json">${escapeHtml(JSON.stringify(server, null, 2))}</pre></div></div></div></section>`;

    document.getElementById('accessDetailsBody').innerHTML = html;
}

function filterTable(type, btn) {
    const rows = document.querySelectorAll('#accessTable tbody tr');
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('filter-active'));
    btn.classList.add('filter-active');
    rows.forEach(row => {
        if (type === 'all') row.style.display = '';
        else if (type === 'allowed') row.style.display = row.classList.contains('row-allowed') ? '' : 'none';
        else if (type === 'blocked') row.style.display = row.classList.contains('row-blocked') ? '' : 'none';
        else if (type === 'pending') row.style.display = row.classList.contains('row-pending') ? '' : 'none';
    });
}

document.addEventListener("DOMContentLoaded", function() {
    const rows = document.querySelectorAll("#accessTable tbody tr");
    const ipCache = {};
    rows.forEach((row, index) => {
        const ipCell = row.querySelector(".ip-target");
        if (!ipCell) return;
        const ip = ipCell.getAttribute("data-ip");
        const countryCell = row.querySelector(".country-cell");
        const ispCell = row.querySelector(".isp-cell");
        const hasData = countryCell.innerText.trim() !== '' && !countryCell.innerText.includes('Wait');

        if (ip === '127.0.0.1' || ip === '::1') {
            countryCell.innerHTML = 'Local';
            ispCell.innerHTML = 'Localhost';
            return;
        }
        if (hasData && ispCell.innerText.trim() !== '' && ispCell.innerText.trim() !== '...') return;
        if (ipCache[ip]) {
            updateUI(countryCell, ispCell, ipCache[ip], hasData);
            return;
        }
        setTimeout(() => {
            fetch(`https://ipwho.is/${ip}`)
                .then(res => res.json())
                .then(data => {
                    if(data.success) {
                        const info = { flag: data.flag.emoji, country: data.country_code, isp: data.connection.isp || data.isp };
                        ipCache[ip] = info;
                        updateUI(countryCell, ispCell, info, hasData);
                    } else if(!hasData) {
                        countryCell.innerText = '-';
                        ispCell.innerText = 'Err';
                    }
                })
                .catch(() => {
                    if(!hasData) {
                        countryCell.innerText = '-';
                        ispCell.innerText = 'Err';
                    }
                });
        }, index * 150);
    });

    document.querySelectorAll('.details-btn').forEach(button => {
        button.addEventListener('click', function() {
            openAccessDetails(Number(button.getAttribute('data-access-index')));
        });
    });

    document.querySelectorAll('.details-back-btn').forEach(button => {
        button.addEventListener('click', function() {
            bootstrap.Tab.getOrCreateInstance(document.getElementById('home-tab')).show();
        });
    });

    function updateUI(cCell, iCell, data, skip) {
        if(!skip) {
            cCell.innerHTML = `${data.flag} ${data.country}`;
            iCell.innerText = data.isp;
        } else if (iCell.innerText.includes('Wait')) {
            iCell.innerText = data.isp;
        }
    }
});
</script>

</body>
</html>
