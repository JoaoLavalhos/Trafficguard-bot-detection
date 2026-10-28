<?php
// TrafficGuard - motor de deteccao de automacao e analise de trafego.
// Baseado na V59 experimental, com ajustes para portfolio: resposta neutra a bloqueios,
// minimizacao de telemetria identificavel e recursos invasivos desativados por padrao.

date_default_timezone_set('America/Sao_Paulo');
error_reporting(0);
session_start();

$requestUri = $_SERVER['REQUEST_URI'] ?? '';
if (preg_match('/\.(ico|png|jpg|jpeg|gif|css|js|svg|woff|ttf|map)$/i', parse_url($requestUri, PHP_URL_PATH))) {
    exit;
}

// Solicita Client Hints opcionais para as proximas requisicoes. Navegadores que
// nao oferecem esses campos continuam funcionando normalmente.
header('Accept-CH: Sec-CH-UA-Full-Version, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform-Version, Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-WoW64, Sec-CH-UA-Model, Sec-CH-UA-Form-Factors, Device-Memory, Sec-CH-Device-Memory, DPR, Width, Viewport-Width, Save-Data, ECT, RTT, Downlink');

$dataDir = __DIR__ . '/data';
if (!is_dir($dataDir)) @mkdir($dataDir, 0750, true);
$arquivoLog = $dataDir . '/dados_acesso.json';
$arquivoConfig = $dataDir . '/config.json';
$arquivoDnsCache = $dataDir . '/dns_cache.json';

$defaults = [
    'lockdown' => 'off',
    'ips' => '', 'ua_keywords' => '', 'os' => '', 'referers' => '', 'countries' => '', 'queries' => '', 'isps' => '',
    'white_ips' => '', 'white_ua' => '', 'white_referers' => '', 'white_countries' => '', 'white_queries' => '', 'white_isps' => '',

    // Novas protecoes
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

$config = $defaults;
if (file_exists($arquivoConfig)) {
    $loaded = json_decode(file_get_contents($arquivoConfig), true);
    if (is_array($loaded)) {
        $config = array_merge($defaults, $loaded);
    }
}

function configOn($config, $key) {
    return isset($config[$key]) && $config[$key] === 'on';
}

function persistentSessionEnabled($config) {
    return configOn($config, 'persistent_session');
}

function configIntValue($config, $key, $fallback = 0, $min = 0, $max = null) {
    $value = isset($config[$key]) && is_numeric($config[$key]) ? (int)$config[$key] : (int)$fallback;
    if ($value < $min) $value = $min;
    if ($max !== null && $value > $max) $value = $max;
    return $value;
}

function postApprovedGraceSeconds($config) {
    return configIntValue($config, 'post_approved_grace_seconds', 45, 0, 600);
}

function technicalGateTolerantEnabled($config) {
    return configOn($config, 'technical_gate_tolerant_mode');
}

function getRealIP() {
    $remote = trim((string)($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'));
    $trustProxy = getenv('TRAFFICGUARD_TRUST_PROXY_HEADERS') === '1';
    if (!$trustProxy) return filter_var($remote, FILTER_VALIDATE_IP) ? $remote : '0.0.0.0';

    $candidates = [];
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) $candidates[] = trim((string)$_SERVER['HTTP_CF_CONNECTING_IP']);
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        foreach (explode(',', (string)$_SERVER['HTTP_X_FORWARDED_FOR']) as $forwardedIp) $candidates[] = trim($forwardedIp);
    }
    if (!empty($_SERVER['HTTP_X_REAL_IP'])) $candidates[] = trim((string)$_SERVER['HTTP_X_REAL_IP']);
    foreach ($candidates as $candidate) {
        if (filter_var($candidate, FILTER_VALIDATE_IP)) return $candidate;
    }
    return filter_var($remote, FILTER_VALIDATE_IP) ? $remote : '0.0.0.0';
}

function getServerSideData($ip) {
    if ($ip == '127.0.0.1' || $ip == '::1') {
        return [
            'country' => 'BR',
            'isp' => 'Localhost',
            'asn' => '',
            'org' => 'Localhost',
            'domain' => '',
            'timezone_id' => 'America/Sao_Paulo',
            'security' => [],
            'source' => 'local',
        ];
    }

    $cacheKey = 'geo_lookup_' . md5($ip);
    if (!empty($_SESSION[$cacheKey]['time']) && (time() - (int)$_SESSION[$cacheKey]['time']) < 3600) {
        return $_SESSION[$cacheKey]['data'];
    }

    $url = "https://ipwho.is/$ip";
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 3);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    $json = curl_exec($ch);
    curl_close($ch);

    $fallback = [
        'country' => 'XX',
        'isp' => 'Unknown',
        'asn' => '',
        'org' => 'Unknown',
        'domain' => '',
        'timezone_id' => '',
        'security' => [],
        'source' => 'ipwho.is',
        'lookup_success' => false,
    ];

    if ($json) {
        $data = json_decode($json, true);
        if (!is_array($data) || (isset($data['success']) && $data['success'] === false)) {
            return $fallback;
        }
        $connection = isset($data['connection']) && is_array($data['connection']) ? $data['connection'] : [];
        $timezone = isset($data['timezone']) && is_array($data['timezone']) ? $data['timezone'] : [];
        $security = isset($data['security']) && is_array($data['security']) ? $data['security'] : [];
        $isp = $connection['isp'] ?? $data['isp'] ?? 'Unknown';
        $country = $data['country_code'] ?? 'XX';
        $result = [
            'country' => $country,
            'isp' => $isp,
            'asn' => isset($connection['asn']) ? (string)$connection['asn'] : '',
            'org' => telemetryString($connection['org'] ?? $connection['asn_org'] ?? $isp, 300),
            'domain' => telemetryString($connection['domain'] ?? '', 300),
            'timezone_id' => telemetryString($timezone['id'] ?? '', 120),
            'timezone_utc' => telemetryString($timezone['utc'] ?? '', 20),
            'security' => $security,
            'source' => 'ipwho.is',
            'lookup_success' => true,
        ];
        $_SESSION[$cacheKey] = ['time' => time(), 'data' => $result];
        return $result;
    }
    return $fallback;
}
function getSystemInfo($ua) {
    $os = 'Desconhecido';
    $reason = 'Allowed';

    if (preg_match('/android/i', $ua)) {
        $os = 'Android';
    } elseif (preg_match('/iphone|ipad|ipod/i', $ua)) {
        $os = 'iOS';
    } elseif (preg_match('/windows/i', $ua)) {
        $os = 'Windows';
    } elseif (preg_match('/macintosh|mac os x/i', $ua)) {
        $os = 'Mac OS';
    } elseif (preg_match('/linux|x11/i', $ua)) {
        $os = 'Linux';
    }

    if (preg_match('/bot|crawl|slurp|spider|facebook|google/i', $ua)) {
        $reason = 'Bot/Crawler';
    }
    return ['os' => $os, 'reason' => $reason];
}

function isMobileUA($ua) {
    return preg_match('/android|iphone|ipad|ipod|mobile/i', $ua) === 1;
}

function checkList($needle, $csvList, $partialMatch = false) {
    if ($needle === null || $needle === '' || empty($csvList)) return false;
    $items = explode(',', $csvList);
    foreach ($items as $item) {
        $item = trim($item);
        if ($item === '') continue;
        if ($partialMatch) {
            if (stripos($needle, $item) !== false) return true;
        } else {
            if (strtoupper(trim($needle)) == strtoupper($item)) return true;
        }
    }
    return false;
}

function addReason(&$reasons, $reason) {
    $reason = trim($reason);
    if ($reason !== '' && !in_array($reason, $reasons, true)) {
        $reasons[] = $reason;
    }
}

function addCheck(&$checks, $key, $label, $result, $enabled, $points, $observed, $expected = '') {
    $checks[] = [
        'key' => $key,
        'label' => $label,
        'result' => $result,
        'enabled' => (bool)$enabled,
        'points' => (int)$points,
        'observed' => $observed,
        'expected' => $expected,
    ];
}

function telemetryString($value, $limit = 2000) {
    $value = str_replace(["\r", "\n", "\0"], ' ', (string)$value);
    return substr(trim($value), 0, $limit);
}

function serverHeaderValue($name) {
    $normalized = strtoupper(str_replace('-', '_', $name));
    if ($normalized === 'CONTENT_TYPE' || $normalized === 'CONTENT_LENGTH') {
        return telemetryString($_SERVER[$normalized] ?? '');
    }
    return telemetryString($_SERVER['HTTP_' . $normalized] ?? '');
}

function rawRequestBody() {
    static $body = null;
    if ($body === null) {
        $read = file_get_contents('php://input');
        $body = is_string($read) ? $read : '';
    }
    return $body;
}

function safeParameterNames($values) {
    if (!is_array($values)) return [];
    $names = [];
    foreach (array_keys($values) as $name) {
        if (count($names) >= 100) break;
        $names[] = telemetryString($name, 120);
    }
    return $names;
}

function authorizationMetadata($authorization) {
    $authorization = trim((string)$authorization);
    $scheme = '';
    if ($authorization !== '' && preg_match('/^([A-Za-z][A-Za-z0-9_-]*)\s+/', $authorization, $match)) {
        $scheme = $match[1];
    }
    return [
        'present' => $authorization !== '',
        'scheme' => $scheme,
        'length' => strlen($authorization),
    ];
}



function rootDomainFromHostname($hostname) {
    $host = strtolower(trim((string)$hostname, ". \t\n\r\0\x0B"));
    if ($host === '' || filter_var($host, FILTER_VALIDATE_IP)) return '';
    $parts = array_values(array_filter(explode('.', $host), function ($part) { return $part !== ''; }));
    $count = count($parts);
    if ($count < 2) return $host;
    $secondLevel = $parts[$count - 2] ?? '';
    $tld = $parts[$count - 1] ?? '';
    $commonSecondLevel = ['com','net','org','gov','edu','mil','co','ac','nom','ind'];
    if (strlen($tld) === 2 && in_array($secondLevel, $commonSecondLevel, true) && $count >= 3) {
        return implode('.', array_slice($parts, -3));
    }
    return implode('.', array_slice($parts, -2));
}

function claimedBotProfileFromUa($ua) {
    $uaLower = strtolower((string)$ua);
    $profiles = [
        'googlebot' => [
            'patterns' => ['googlebot','adsbot-google','mediapartners-google','apis-google','feedfetcher-google','google-inspectiontool'],
            'domains' => ['googlebot.com','google.com'],
        ],
        'bingbot' => [
            'patterns' => ['bingbot','msnbot'],
            'domains' => ['search.msn.com','bing.com'],
        ],
        'yandex' => [
            'patterns' => ['yandexbot','yandex'],
            'domains' => ['yandex.com','yandex.ru','yandex.net'],
        ],
        'duckduckbot' => [
            'patterns' => ['duckduckbot'],
            'domains' => ['duckduckgo.com'],
        ],
        'baidu' => [
            'patterns' => ['baiduspider','baidu'],
            'domains' => ['baidu.com'],
        ],
        'facebook' => [
            'patterns' => ['facebookexternalhit','facebot'],
            'domains' => ['facebook.com','tfbnw.net','fbsv.net'],
        ],
        'twitter_x' => [
            'patterns' => ['twitterbot'],
            'domains' => ['twitter.com','x.com'],
        ],
        'linkedin' => [
            'patterns' => ['linkedinbot'],
            'domains' => ['linkedin.com'],
        ],
        'pinterest' => [
            'patterns' => ['pinterestbot'],
            'domains' => ['pinterest.com'],
        ],
    ];
    foreach ($profiles as $type => $profile) {
        foreach ($profile['patterns'] as $pattern) {
            if ($pattern !== '' && strpos($uaLower, $pattern) !== false) {
                return [
                    'type' => $type,
                    'expected_domains' => $profile['domains'],
                ];
            }
        }
    }
    return ['type' => '', 'expected_domains' => []];
}

function reverseDnsClassification($ptrHostname, $ua) {
    $ptr = strtolower((string)$ptrHostname);
    $hostingPatterns = ['amazonaws','compute','cloud','googleusercontent','digitalocean','linode','vultr','hetzner','ovh','azure','microsoft','oraclecloud','leaseweb','server','vps','host','hosting','datacenter','colo','cloudflare'];
    $residentialPatterns = ['dynamic','dyn','customer','client','subscriber','broadband','cable','fibra','fiber','ftth','dsl','pppoe','virtua','velox','residential'];
    $mobilePatterns = ['mobile','3g','4g','5g','lte','gprs','edge','claro','vivo','tim','telefonica','oi','nextel','movistar'];
    $crawlerPatterns = ['googlebot','bingbot','msnbot','yandex','baiduspider','duckduckbot','crawler','spider','search.msn','facebookexternalhit','facebot','twitterbot','linkedinbot','pinterestbot'];

    $hasAny = function ($patterns) use ($ptr) {
        foreach ($patterns as $pattern) {
            if ($pattern !== '' && strpos($ptr, $pattern) !== false) return true;
        }
        return false;
    };

    $looksCrawler = $ptr !== '' && $hasAny($crawlerPatterns);
    $looksHosting = $ptr !== '' && $hasAny($hostingPatterns);
    $looksResidential = $ptr !== '' && $hasAny($residentialPatterns);
    $looksMobile = $ptr !== '' && $hasAny($mobilePatterns);

    $category = 'unknown';
    if ($looksCrawler) $category = 'crawler';
    elseif ($looksHosting) $category = 'hosting';
    elseif ($looksMobile) $category = 'mobile';
    elseif ($looksResidential) $category = 'residential';

    $claimed = claimedBotProfileFromUa($ua);
    $claimedValid = null;
    if ($claimed['type'] !== '') {
        $claimedValid = false;
        foreach ($claimed['expected_domains'] as $domain) {
            if ($ptr !== '' && (substr($ptr, -strlen($domain)) === $domain || $ptr === $domain)) {
                $claimedValid = true;
                break;
            }
        }
    }

    return [
        'ptr_domain' => rootDomainFromHostname($ptr),
        'ptr_category' => $category,
        'ptr_looks_hosting' => $looksHosting,
        'ptr_looks_residential' => $looksResidential,
        'ptr_looks_mobile' => $looksMobile,
        'ptr_looks_crawler' => $looksCrawler,
        'claimed_bot_type' => $claimed['type'],
        'claimed_bot_ptr_valid' => $claimedValid,
        'claimed_bot_ptr_expected_domains' => $claimed['expected_domains'],
    ];
}

function getReverseDnsFullData($ip, $ua = '') {
    $started = microtime(true);
    $ip = trim((string)$ip);
    $base = [
        'enabled' => true,
        'lookup_attempted' => false,
        'cache_hit' => false,
        'lookup_ms' => null,
        'ptr_hostname' => '',
        'ptr_available' => false,
        'ptr_domain' => '',
        'ptr_category' => 'unknown',
        'ptr_looks_hosting' => false,
        'ptr_looks_residential' => false,
        'ptr_looks_mobile' => false,
        'ptr_looks_crawler' => false,
        'claimed_bot_type' => '',
        'claimed_bot_ptr_valid' => null,
        'claimed_bot_ptr_expected_domains' => [],
        'lookup_skipped_reason' => '',
        'cache_ttl_seconds' => 604800,
        'privacy_note' => 'Coleta somente hostname PTR e classificacoes derivadas; nao salva conteudo do visitante.',
    ];

    if ($ip === '' || $ip === '0.0.0.0' || !filter_var($ip, FILTER_VALIDATE_IP)) {
        $base['lookup_skipped_reason'] = 'ip_invalido';
        return $base;
    }
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        $base['lookup_skipped_reason'] = 'ip_privado_ou_reservado';
        return $base;
    }

    $cacheFile = isset($GLOBALS['arquivoDnsCache']) ? (string)$GLOBALS['arquivoDnsCache'] : 'dns_cache.json';
    $cacheKey = md5($ip);
    $ttl = 604800; // 7 dias
    $cache = readJsonFile($cacheFile, []);
    if (isset($cache[$cacheKey]) && is_array($cache[$cacheKey]) && isset($cache[$cacheKey]['time'], $cache[$cacheKey]['data']) && (time() - (int)$cache[$cacheKey]['time']) < $ttl) {
        $cached = $cache[$cacheKey]['data'];
        if (is_array($cached)) {
            $cached['cache_hit'] = true;
            $cached['lookup_attempted'] = true;
            $cached['lookup_ms'] = 0;
            $cached['cache_ttl_seconds'] = $ttl;
            return array_merge($base, $cached);
        }
    }

    $base['lookup_attempted'] = true;
    $ptr = @gethostbyaddr($ip);
    $lookupMs = round(max(0, (microtime(true) - $started) * 1000), 2);
    $ptrHostname = ($ptr !== false && strtolower((string)$ptr) !== strtolower($ip)) ? telemetryString(strtolower((string)$ptr), 300) : '';
    $classification = reverseDnsClassification($ptrHostname, $ua);

    $result = array_merge($base, $classification, [
        'lookup_attempted' => true,
        'cache_hit' => false,
        'lookup_ms' => $lookupMs,
        'ptr_hostname' => $ptrHostname,
        'ptr_available' => $ptrHostname !== '',
        'lookup_skipped_reason' => '',
        'cache_ttl_seconds' => $ttl,
    ]);

    $cache[$cacheKey] = [
        'time' => time(),
        'ip_hash' => hash('sha256', $ip),
        'data' => $result,
    ];
    if (count($cache) > 1000) {
        uasort($cache, function ($a, $b) { return (int)($b['time'] ?? 0) <=> (int)($a['time'] ?? 0); });
        $cache = array_slice($cache, 0, 1000, true);
    }
    writeJsonFile($cacheFile, $cache);

    return $result;
}

function deviceMemoryClientHintTelemetry($ua) {
    $legacy = serverHeaderValue('Device-Memory');
    $secCh = serverHeaderValue('Sec-CH-Device-Memory');
    $selected = $secCh !== '' ? $secCh : $legacy;
    $clean = str_replace(['"', "'", ' '], '', trim((string)$selected));
    $numeric = is_numeric($clean) ? (float)$clean : null;
    return [
        'legacy' => $legacy,
        'sec_ch' => $secCh,
        'effective_value' => $numeric,
        'source' => $secCh !== '' ? 'Sec-CH-Device-Memory' : ($legacy !== '' ? 'Device-Memory' : ''),
        'present' => $legacy !== '' || $secCh !== '',
        'legacy_present' => $legacy !== '',
        'sec_ch_present' => $secCh !== '',
        'is_high' => $numeric !== null && $numeric >= 16,
        'is_unusual_for_mobile' => isMobileUA($ua) && $numeric !== null && $numeric >= 16,
        'note' => 'Informativo: em mobile/WebView, valores altos como 16/32 podem indicar automacao ou spoofing, mas nao bloqueiam sozinhos.',
    ];
}


function parseDeviceMemoryHeaderNumber($value) {
    $clean = trim((string)$value);
    if ($clean === '') return null;
    $clean = str_replace(['"', "'", ' '], '', $clean);
    $clean = str_replace(',', '.', $clean);
    return is_numeric($clean) ? (float)$clean : null;
}

function normalizeFlowAction($action) {
    $action = telemetryString($action, 120);
    $aliases = [
        'pixel' => 'media_asset',
        'iframe_ping' => 'frame_init',
        'sw_lab_js' => 'worker_asset',
        'stage1_code' => 'base_asset',
        'stage2_code' => 'runtime_asset',
        'render_check' => 'view_state',
        'client_check' => 'session_sync',
        'client_fail' => 'session_event',
        'honeypot' => 'nav_item',
        'blocked_page' => 'status_page',
    ];
    return $aliases[$action] ?? $action;
}

function currentFlowAction() {
    $raw = $_GET['flow_action'] ?? '';
    return normalizeFlowAction($raw);
}

function currentRequestKind() {
    $method = httpMethodBucket($_SERVER['REQUEST_METHOD'] ?? 'GET');
    $action = currentFlowAction();
    $pageID = pageId();
    $scope = (string)($_SESSION['active_access_scope_' . $pageID] ?? '');

    if ($action === 'media_asset') return 'resource_pixel';
    if ($action === 'frame_init') return 'render_iframe_ping';
    if ($action === 'worker_asset' && $method === 'GET') return 'service_worker_lab_js';
    if ($action === 'base_asset' && $method === 'GET') return 'stage1_code_get';
    if ($action === 'runtime_asset' && $method === 'GET') return 'stage2_code_get';
    if ($action === 'view_state' && $method === 'POST') return 'render_check_post';
    if ($action === 'session_sync' && $method === 'POST') return 'client_check_post';
    if ($action === 'session_event' && $method === 'POST') return 'client_fail_post';
    if ($action === 'nav_item') return 'honeypot';
    if ($action === 'status_page') return 'blocked_page';

    if (isset($_GET['__cbh'])) return 'preflight_http_return';
    if (isset($_GET['__cbj'])) return 'preflight_js_return';

    if ($method === 'GET') {
        if ($scope !== '') {
            $httpOk = !empty($_SESSION['preflight_http_ok_' . $scope]);
            $jsOk = !empty($_SESSION['preflight_js_ok_' . $scope]);
            if (!$httpOk) return 'page_initial_get';
            if ($httpOk && !$jsOk) return 'preflight_js_bootstrap_get';
            if ($httpOk && $jsOk) return 'gate_page_get';
        }
        return 'page_get';
    }

    if ($method === 'POST') return 'post_other';
    if ($method === 'HEAD') return 'head_request';
    return 'other_method';
}

function requestKindIsInternal($kind) {
    return in_array((string)$kind, [
        'resource_pixel',
        'render_iframe_ping',
        'service_worker_lab_js',
        'stage1_code_get',
        'stage2_code_get',
        'render_check_post',
        'client_fail_post',
        'honeypot',
        'blocked_page',
        'preflight_http_return',
        'preflight_js_return',
    ], true);
}

function computeVariance($values) {
    $count = count($values);
    if ($count < 2) return null;
    $mean = array_sum($values) / $count;
    $variance = 0.0;
    foreach ($values as $value) {
        $delta = (float)$value - $mean;
        $variance += $delta * $delta;
    }
    return $variance / $count;
}

function timingStatsFromTimestamps($timestamps) {
    $clean = [];
    foreach ($timestamps as $timestamp) {
        if (is_numeric($timestamp)) $clean[] = (float)$timestamp;
    }
    sort($clean, SORT_NUMERIC);
    $intervals = [];
    for ($i = 1; $i < count($clean); $i++) {
        $intervals[] = max(0, $clean[$i] - $clean[$i - 1]);
    }
    $variance = computeVariance($intervals);
    $stddev = $variance === null ? null : sqrt($variance);
    $mean = count($intervals) > 0 ? array_sum($intervals) / count($intervals) : null;
    return [
        'points_count' => count($clean),
        'interval_count' => count($intervals),
        'mean_interval_seconds' => $mean === null ? null : round($mean, 6),
        'variance_seconds2' => $variance === null ? null : round($variance, 6),
        'stddev_seconds' => $stddev === null ? null : round($stddev, 6),
        'interval_sample_seconds' => array_map(function ($value) { return round((float)$value, 6); }, array_slice($intervals, -12)),
    ];
}

function flowTimingFromState($flow, $expectedDelayMs) {
    $firstGet = isset($flow['first_get_unix']) ? (float)$flow['first_get_unix'] : null;
    $secondGet = isset($flow['second_get_unix']) ? (float)$flow['second_get_unix'] : null;
    $post = isset($flow['client_check_post_unix']) ? (float)$flow['client_check_post_unix'] : null;
    $get1ToGet2 = ($firstGet !== null && $secondGet !== null) ? round(max(0, ($secondGet - $firstGet) * 1000), 2) : null;
    $get2ToPost = ($secondGet !== null && $post !== null) ? round(max(0, ($post - $secondGet) * 1000), 2) : null;
    $get1ToPost = ($firstGet !== null && $post !== null) ? round(max(0, ($post - $firstGet) * 1000), 2) : null;
    $postAfterExpected = ($get2ToPost !== null) ? round($get2ToPost - $expectedDelayMs, 2) : null;

    return [
        'flow_id' => (string)($flow['flow_id'] ?? ''),
        'first_get_unix' => $firstGet === null ? null : round($firstGet, 6),
        'first_get_kind' => (string)($flow['first_get_kind'] ?? ''),
        'second_get_unix' => $secondGet === null ? null : round($secondGet, 6),
        'second_get_kind' => (string)($flow['second_get_kind'] ?? ''),
        'client_check_post_unix' => $post === null ? null : round($post, 6),
        'get1_to_get2_ms' => $get1ToGet2,
        'get2_to_post_ms' => $get2ToPost,
        'get1_to_post_ms' => $get1ToPost,
        'expected_client_delay_ms' => $expectedDelayMs,
        'post_after_expected_delay_ms' => $postAfterExpected,
        'post_faster_than_expected_by_250ms' => $postAfterExpected !== null && $postAfterExpected < -250,
        'post_near_exact_expected_delay_50ms' => $postAfterExpected !== null && abs($postAfterExpected) <= 50,
        'raw_request_count' => (int)($flow['raw_request_count'] ?? 0),
        'internal_request_count' => (int)($flow['internal_request_count'] ?? 0),
        'behavioral_request_count' => (int)($flow['behavioral_request_count'] ?? 0),
        'raw_get_count' => (int)($flow['raw_get_count'] ?? 0),
        'raw_post_count' => (int)($flow['raw_post_count'] ?? 0),
        'behavioral_get_count' => (int)($flow['behavioral_get_count'] ?? 0),
        'behavioral_post_count' => (int)($flow['behavioral_post_count'] ?? 0),
        'sequence' => array_slice(is_array($flow['sequence'] ?? null) ? $flow['sequence'] : [], -25),
        'raw_timing' => timingStatsFromTimestamps(is_array($flow['raw_timestamps'] ?? null) ? $flow['raw_timestamps'] : []),
        'behavioral_timing' => timingStatsFromTimestamps(is_array($flow['behavioral_timestamps'] ?? null) ? $flow['behavioral_timestamps'] : []),
        'note' => 'Campos informativos. Nao bloqueiam por tempo; servem para comparar celular real, WebView e automacao.',
    ];
}

function networkIdentityFromGeoData($ip, $countryCode, $ispName, $reverseDns = []) {
    $geo = isset($GLOBALS['geoData']) && is_array($GLOBALS['geoData']) ? $GLOBALS['geoData'] : [];
    return [
        'ip' => $ip,
        'country' => $countryCode,
        'isp' => $ispName,
        'asn' => telemetryString($geo['asn'] ?? '', 80),
        'org' => telemetryString($geo['org'] ?? '', 300),
        'domain' => telemetryString($geo['domain'] ?? '', 300),
        'timezone_id' => telemetryString($geo['timezone_id'] ?? '', 120),
        'timezone_utc' => telemetryString($geo['timezone_utc'] ?? '', 20),
        'security' => is_array($geo['security'] ?? null) ? $geo['security'] : [],
        'lookup_source' => telemetryString($geo['source'] ?? '', 80),
        'lookup_success' => !empty($geo['lookup_success']),
        'reverse_dns' => is_array($reverseDns) ? $reverseDns : [],
    ];
}

function sessionTelemetryMetadata() {
    static $metadata = null;
    if ($metadata !== null) return $metadata;

    $now = microtime(true);
    $previous = isset($_SESSION['server_telemetry_last_request']) ? (float)$_SESSION['server_telemetry_last_request'] : null;
    $first = isset($_SESSION['server_telemetry_first_request']) ? (float)$_SESSION['server_telemetry_first_request'] : $now;

    $activeConfig = isset($GLOBALS['config']) && is_array($GLOBALS['config']) ? $GLOBALS['config'] : [];
    $pageID = pageId();
    $activeTrace = (string)($_SESSION['active_access_trace_' . $pageID] ?? '');
    $method = strtoupper(trim((string)($_SERVER['REQUEST_METHOD'] ?? 'GET')));
    $methodBucket = httpMethodBucket($method);
    $requestKind = currentRequestKind();
    $isInternal = requestKindIsInternal($requestKind);

    // Contagem real por sessão: registra o método de toda requisição que chega ao PHP,
    // mesmo quando o log visual evita duplicatas muito rápidas.
    $getCount = isset($_SESSION['server_telemetry_get_count']) ? (int)$_SESSION['server_telemetry_get_count'] : 0;
    $postCount = isset($_SESSION['server_telemetry_post_count']) ? (int)$_SESSION['server_telemetry_post_count'] : 0;
    $headCount = isset($_SESSION['server_telemetry_head_count']) ? (int)$_SESSION['server_telemetry_head_count'] : 0;
    $otherCount = isset($_SESSION['server_telemetry_other_count']) ? (int)$_SESSION['server_telemetry_other_count'] : 0;

    if ($methodBucket === 'GET') {
        $getCount++;
        $_SESSION['server_telemetry_get_count'] = $getCount;
    } elseif ($methodBucket === 'POST') {
        $postCount++;
        $_SESSION['server_telemetry_post_count'] = $postCount;
    } elseif ($methodBucket === 'HEAD') {
        $headCount++;
        $_SESSION['server_telemetry_head_count'] = $headCount;
    } else {
        $otherCount++;
        $_SESSION['server_telemetry_other_count'] = $otherCount;
    }

    $count = isset($_SESSION['server_telemetry_request_count']) ? ((int)$_SESSION['server_telemetry_request_count'] + 1) : 1;

    // Entropia de tempo no estilo do trackerExemplo:
    // usa os 5 ultimos timestamps da sessao e calcula a variancia dos 4 intervalos.
    $timestamps = $_SESSION['server_telemetry_timestamps'] ?? [];
    if (!is_array($timestamps)) $timestamps = [];
    $timestamps[] = $now;
    if (count($timestamps) > 5) array_shift($timestamps);
    $_SESSION['server_telemetry_timestamps'] = $timestamps;

    $timingIntervals = [];
    $timingMean = null;
    $timingVariance = null;
    if (count($timestamps) === 5) {
        for ($i = 1; $i < 5; $i++) {
            $timingIntervals[] = max(0, (float)$timestamps[$i] - (float)$timestamps[$i - 1]);
        }
        $timingMean = array_sum($timingIntervals) / count($timingIntervals);
        $timingVariance = computeVariance($timingIntervals);
    }

    // Fluxo informativo GET -> GET -> POST. Nao adiciona motivo de bloqueio.
    $flowKey = 'server_telemetry_flow_' . $pageID;
    $flow = $_SESSION[$flowKey] ?? [];
    if (!is_array($flow)) $flow = [];
    if (empty($flow['flow_id'])) {
        $flowSeed = $activeTrace !== '' ? $activeTrace : (session_id() . '|' . $pageID . '|' . sprintf('%.6f', $first));
        $flow['flow_id'] = substr(hash('sha256', $flowSeed), 0, 16);
    }
    $flow['raw_request_count'] = (int)($flow['raw_request_count'] ?? 0) + 1;
    if ($isInternal) $flow['internal_request_count'] = (int)($flow['internal_request_count'] ?? 0) + 1;
    else $flow['behavioral_request_count'] = (int)($flow['behavioral_request_count'] ?? 0) + 1;
    if ($methodBucket === 'GET') $flow['raw_get_count'] = (int)($flow['raw_get_count'] ?? 0) + 1;
    if ($methodBucket === 'POST') $flow['raw_post_count'] = (int)($flow['raw_post_count'] ?? 0) + 1;
    if (!$isInternal && $methodBucket === 'GET') $flow['behavioral_get_count'] = (int)($flow['behavioral_get_count'] ?? 0) + 1;
    if (!$isInternal && $methodBucket === 'POST') $flow['behavioral_post_count'] = (int)($flow['behavioral_post_count'] ?? 0) + 1;

    $flow['raw_timestamps'] = is_array($flow['raw_timestamps'] ?? null) ? $flow['raw_timestamps'] : [];
    $flow['raw_timestamps'][] = $now;
    if (count($flow['raw_timestamps']) > 25) $flow['raw_timestamps'] = array_slice($flow['raw_timestamps'], -25);

    if (!$isInternal) {
        $flow['behavioral_timestamps'] = is_array($flow['behavioral_timestamps'] ?? null) ? $flow['behavioral_timestamps'] : [];
        $flow['behavioral_timestamps'][] = $now;
        if (count($flow['behavioral_timestamps']) > 25) $flow['behavioral_timestamps'] = array_slice($flow['behavioral_timestamps'], -25);
    }

    if ($methodBucket === 'GET' && !$isInternal) {
        if (empty($flow['first_get_unix'])) {
            $flow['first_get_unix'] = $now;
            $flow['first_get_kind'] = $requestKind;
        } elseif (empty($flow['second_get_unix']) && abs($now - (float)$flow['first_get_unix']) > 0.001) {
            $flow['second_get_unix'] = $now;
            $flow['second_get_kind'] = $requestKind;
        }
    }
    if ($requestKind === 'client_check_post') {
        $flow['client_check_post_unix'] = $now;
    }

    $flow['sequence'] = is_array($flow['sequence'] ?? null) ? $flow['sequence'] : [];
    $flow['sequence'][] = [
        'at_unix' => round($now, 6),
        'method' => $methodBucket,
        'kind' => $requestKind,
        'action' => currentFlowAction(),
        'internal' => $isInternal,
    ];
    if (count($flow['sequence']) > 25) $flow['sequence'] = array_slice($flow['sequence'], -25);
    $_SESSION[$flowKey] = $flow;

    // Apenas coleta informativa: registra se houve POST, sem usar delay minimo configuravel.
    // A velocidade do POST fica em flow_timing.get2_to_post_ms / get1_to_post_ms.
    $postStatus = ($methodBucket === 'POST') ? ($count === 1 ? 'post_first_request' : 'post_seen') : 'not_post';

    $_SESSION['server_telemetry_first_request'] = $first;
    $_SESSION['server_telemetry_last_request'] = $now;
    $_SESSION['server_telemetry_request_count'] = $count;

    $expectedDelayMs = max(300, (int)($activeConfig['client_check_delay'] ?? 1500));
    $flowTiming = flowTimingFromState($flow, $expectedDelayMs);

    $sessionId = session_id();
    $metadata = [
        'cookie_name' => session_name(),
        'cookie_received' => session_name() !== '' && isset($_COOKIE[session_name()]),
        'id_hash' => $sessionId === '' ? '' : hash('sha256', $sessionId),
        'flow_id' => (string)($flow['flow_id'] ?? ''),
        'request_kind' => $requestKind,
        'request_kind_internal' => $isInternal,
        'request_count' => $count,
        'get_count' => $getCount,
        'post_count' => $postCount,
        'head_count' => $headCount,
        'other_method_count' => $otherCount,
        'method_counts' => [
            'GET' => $getCount,
            'POST' => $postCount,
            'HEAD' => $headCount,
            'OTHER' => $otherCount,
        ],
        'current_method_bucket' => $methodBucket,
        'first_seen_unix' => round($first, 6),
        'age_seconds' => round(max(0, $now - $first), 3),
        'previous_request_gap_ms' => $previous === null ? null : round(max(0, ($now - $previous) * 1000), 2),
        'timing_variance' => $timingVariance !== null ? round($timingVariance, 6) : null,
        'timing_mean_interval_seconds' => $timingMean !== null ? round($timingMean, 6) : null,
        'timing_interval_sample_seconds' => array_map(function ($value) { return round((float)$value, 6); }, $timingIntervals),
        'timing_sample_size' => count($timestamps),
        'mechanical_timing_suspected' => $timingVariance !== null && $timingVariance < 0.005,
        'mechanical_timing_rule' => 'Informativo: true quando a variancia dos 4 ultimos intervalos da sessao fica abaixo de 0.005. Nao bloqueia sozinho nesta versao.',
        'post_status' => $postStatus,
        'flow_timing' => $flowTiming,
    ];
    return $metadata;
}
function preflightTelemetryMetadata() {
    $pageID = pageId();
    $scope = (string)($_SESSION['active_access_scope_' . $pageID] ?? '');
    if ($scope === '') {
        return [
            'active' => false,
            'completed_roundtrips' => 0,
        ];
    }
    $started = (float)($_SESSION['preflight_attempt_started_' . $scope] ?? 0);
    $httpIssued = (float)($_SESSION['preflight_http_issued_' . $scope] ?? 0);
    $httpCompleted = (float)($_SESSION['preflight_http_completed_' . $scope] ?? 0);
    $jsIssued = (float)($_SESSION['preflight_js_issued_' . $scope] ?? 0);
    $jsCompleted = (float)($_SESSION['preflight_js_completed_' . $scope] ?? 0);
    return [
        'active' => true,
        'scope_hash' => hash('sha256', $scope),
        'completed_roundtrips' => ($httpCompleted > 0 ? 1 : 0) + ($jsCompleted > 0 ? 1 : 0),
        'http_cookie_issued' => $httpIssued > 0,
        'http_cookie_completed' => $httpCompleted > 0,
        'http_roundtrip_ms' => ($httpIssued > 0 && $httpCompleted >= $httpIssued) ? round(($httpCompleted - $httpIssued) * 1000, 2) : null,
        'javascript_cookie_issued' => $jsIssued > 0,
        'javascript_cookie_completed' => $jsCompleted > 0,
        'javascript_roundtrip_ms' => ($jsIssued > 0 && $jsCompleted >= $jsIssued) ? round(($jsCompleted - $jsIssued) * 1000, 2) : null,
        'elapsed_since_attempt_start_ms' => $started > 0 ? round(max(0, (microtime(true) - $started) * 1000), 2) : null,
    ];
}

function responseMetadataAtLogTime() {
    $responseHeaders = headers_list();
    $headerNames = [];
    $contentType = '';
    $locationPresent = false;
    foreach ($responseHeaders as $headerLine) {
        $parts = explode(':', $headerLine, 2);
        $name = telemetryString($parts[0] ?? '', 100);
        if ($name !== '') $headerNames[] = $name;
        if (strcasecmp($name, 'Content-Type') === 0) $contentType = telemetryString($parts[1] ?? '');
        if (strcasecmp($name, 'Location') === 0) $locationPresent = true;
    }
    $bufferLength = ob_get_length();
    return [
        'status_at_log' => http_response_code(),
        'content_type_at_log' => $contentType,
        'header_names_at_log' => array_values(array_unique($headerNames)),
        'location_header_present_at_log' => $locationPresent,
        'buffered_bytes_at_log' => $bufferLength === false ? 0 : (int)$bufferLength,
        'note' => 'Valores observados no instante do registro; a resposta pode ser finalizada depois.',
    ];
}


function acceptHeaderTelemetryDetails($acceptHeader) {
    $raw = telemetryString($acceptHeader, 4000);
    $items = [];
    $htmlLike = false;
    $hasXhtml = false;
    $hasXml = false;
    $hasAvif = false;
    $hasWebp = false;
    $hasSignedExchange = false;
    $hasWildcard = false;
    $parts = array_map('trim', explode(',', $raw));
    foreach ($parts as $index => $part) {
        if ($part === '') continue;
        $segments = array_map('trim', explode(';', $part));
        $media = strtolower((string)array_shift($segments));
        $params = [];
        $q = null;
        foreach ($segments as $segment) {
            if ($segment === '') continue;
            $pair = explode('=', $segment, 2);
            $paramKey = strtolower(trim((string)($pair[0] ?? '')));
            $paramValue = trim((string)($pair[1] ?? ''));
            if ($paramKey === '') continue;
            $params[$paramKey] = $paramValue;
            if ($paramKey === 'q' && is_numeric($paramValue)) $q = (float)$paramValue;
        }
        $type = '';
        $subtype = '';
        if (strpos($media, '/') !== false) {
            $mediaParts = explode('/', $media, 2);
            $type = $mediaParts[0] ?? '';
            $subtype = $mediaParts[1] ?? '';
        }
        if ($media === 'text/html') $htmlLike = true;
        if ($media === 'application/xhtml+xml') $hasXhtml = true;
        if ($media === 'application/xml' || $media === 'text/xml') $hasXml = true;
        if ($media === 'image/avif') $hasAvif = true;
        if ($media === 'image/webp') $hasWebp = true;
        if ($media === 'application/signed-exchange') $hasSignedExchange = true;
        if ($media === '*/*' || $type === '*' || $subtype === '*') $hasWildcard = true;
        $items[] = [
            'position' => count($items) + 1,
            'raw' => telemetryString($part, 500),
            'media' => telemetryString($media, 120),
            'type' => telemetryString($type, 80),
            'subtype' => telemetryString($subtype, 120),
            'q' => $q,
            'params' => $params,
        ];
        if (count($items) >= 40) break;
    }
    return [
        'raw' => $raw,
        'length' => strlen($raw),
        'present' => $raw !== '',
        'item_count' => count($items),
        'items' => $items,
        'has_text_html' => $htmlLike,
        'has_application_xhtml_xml' => $hasXhtml,
        'has_application_xml_or_text_xml' => $hasXml,
        'has_image_avif' => $hasAvif,
        'has_image_webp' => $hasWebp,
        'has_application_signed_exchange' => $hasSignedExchange,
        'has_wildcard' => $hasWildcard,
        'looks_like_html_navigation_accept' => $htmlLike && ($hasXhtml || $hasXml || $hasWildcard),
        'sha256' => $raw === '' ? '' : hash('sha256', $raw),
    ];
}

function initialNavigationHeadersTelemetry($requestKind) {
    $pageID = pageId();
    $key = 'initial_navigation_headers_' . $pageID;
    if (!isset($_SESSION[$key]) || !is_array($_SESSION[$key])) {
        $method = httpMethodBucket($_SERVER['REQUEST_METHOD'] ?? 'GET');
        $action = currentFlowAction();
        $accept = serverHeaderValue('Accept');
        $secFetchMode = serverHeaderValue('Sec-Fetch-Mode');
        $secFetchDest = serverHeaderValue('Sec-Fetch-Dest');
        $isInternal = requestKindIsInternal($requestKind);
        $isNavigationLike = $method === 'GET' && !$isInternal && $action === '' && (
            $accept !== '' ||
            strcasecmp($secFetchMode, 'navigate') === 0 ||
            strcasecmp($secFetchDest, 'document') === 0
        );
        if ($isNavigationLike) {
            $requestUri = telemetryString($_SERVER['REQUEST_URI'] ?? '', 4000);
            $requestPath = parse_url($requestUri, PHP_URL_PATH);
            if (!is_string($requestPath)) $requestPath = '';
            $headerNames = [];
            foreach ($_SERVER as $serverKey => $unused) {
                if (strpos($serverKey, 'HTTP_') === 0) {
                    $headerNames[] = str_replace('_', '-', substr($serverKey, 5));
                }
            }
            $_SESSION[$key] = [
                'captured' => true,
                'captured_at_unix' => round(microtime(true), 6),
                'captured_at_iso8601' => date('c'),
                'method' => $method,
                'request_kind' => telemetryString($requestKind, 120),
                'request_uri' => $requestUri,
                'path' => telemetryString($requestPath, 2000),
                'accept' => $accept,
                'accept_details' => acceptHeaderTelemetryDetails($accept),
                'accept_language' => serverHeaderValue('Accept-Language'),
                'accept_encoding' => serverHeaderValue('Accept-Encoding'),
                'sec_fetch_site' => serverHeaderValue('Sec-Fetch-Site'),
                'sec_fetch_mode' => $secFetchMode,
                'sec_fetch_dest' => $secFetchDest,
                'sec_fetch_user' => serverHeaderValue('Sec-Fetch-User'),
                'upgrade_insecure_requests' => serverHeaderValue('Upgrade-Insecure-Requests'),
                'user_agent' => serverHeaderValue('User-Agent'),
                'sec_ch_ua' => serverHeaderValue('Sec-CH-UA'),
                'sec_ch_ua_mobile' => serverHeaderValue('Sec-CH-UA-Mobile'),
                'sec_ch_ua_platform' => serverHeaderValue('Sec-CH-UA-Platform'),
                'header_count' => count($headerNames),
                'header_names' => array_values(array_unique($headerNames)),
                'note' => 'Snapshot server-side do primeiro GET de navegacao observado na sessao/pagina. Nao depende de JavaScript nem de renderizacao da pagina.',
            ];
        }
    }
    if (isset($_SESSION[$key]) && is_array($_SESSION[$key])) {
        return $_SESSION[$key];
    }
    return [
        'captured' => false,
        'current_method' => httpMethodBucket($_SERVER['REQUEST_METHOD'] ?? 'GET'),
        'current_request_kind' => telemetryString($requestKind, 120),
        'note' => 'Ainda nao houve GET de navegacao elegivel para snapshot nesta sessao/pagina.',
    ];
}


function normalizeRefererHost($host) {
    $host = strtolower(trim((string)$host));
    if ($host === '') return '';
    if (strpos($host, ':') !== false && substr_count($host, ':') === 1) {
        $parts = explode(':', $host, 2);
        $host = $parts[0];
    }
    return $host;
}

function currentRequestRefererHeader() {
    $referer = serverHeaderValue('Referer');
    return $referer === '' ? 'Direto' : telemetryString($referer, 2000);
}

function refererLooksInternalTracker($referer) {
    $referer = trim((string)$referer);
    if ($referer === '' || $referer === 'Direto') return true;

    $refererHost = normalizeRefererHost(parse_url($referer, PHP_URL_HOST) ?: '');
    $currentHost = normalizeRefererHost($_SERVER['HTTP_HOST'] ?? '');
    if ($refererHost === '' || $currentHost === '' || $refererHost !== $currentHost) return false;

    $refererPath = (string)(parse_url($referer, PHP_URL_PATH) ?: '');
    $scriptPath = (string)($_SERVER['SCRIPT_NAME'] ?? '');
    $refererBase = basename($refererPath);
    $scriptBase = basename($scriptPath);
    $refererQuery = (string)(parse_url($referer, PHP_URL_QUERY) ?: '');

    if ($scriptBase !== '' && $refererBase === $scriptBase) return true;
    if ($refererQuery !== '' && preg_match('/(^|&)(flow_action|__cbh|__cbj)=/i', $refererQuery)) return true;

    return false;
}

function landingRefererForAccess($pageID, $scope, $currentReferer) {
    $currentReferer = trim((string)$currentReferer);
    $currentReferer = $currentReferer === '' ? 'Direto' : telemetryString($currentReferer, 2000);

    $landingKey = 'landing_referer_' . $scope;
    $currentKey = 'current_request_referer_' . $scope;
    $_SESSION[$currentKey] = $currentReferer;

    $currentIsUsableLanding = ($currentReferer !== 'Direto' && !refererLooksInternalTracker($currentReferer));
    if (!isset($_SESSION[$landingKey]) || $_SESSION[$landingKey] === '' || ($_SESSION[$landingKey] === 'Direto' && $currentIsUsableLanding)) {
        $_SESSION[$landingKey] = $currentIsUsableLanding ? $currentReferer : 'Direto';
    }

    return (string)($_SESSION[$landingKey] ?? 'Direto');
}

function collectServerData($ip, $countryCode, $ispName, $currentOS, $ua, $referer, $queryString) {
    list($httpGuardCookie, $jsGuardCookie) = guardCookieNames(pageId());
    $requestUri = telemetryString($_SERVER['REQUEST_URI'] ?? '', 4000);
    $requestPath = parse_url($requestUri, PHP_URL_PATH);
    if (!is_string($requestPath)) $requestPath = '';
    $authorization = serverHeaderValue('Authorization');
    $cookieHeader = serverHeaderValue('Cookie');
    $rawBody = rawRequestBody();
    $contentType = serverHeaderValue('Content-Type');
    $currentRequestReferer = currentRequestRefererHeader();
    $jsonKeys = [];
    if ($rawBody !== '' && stripos($contentType, 'json') !== false) {
        $decodedBody = json_decode($rawBody, true);
        if (is_array($decodedBody)) $jsonKeys = safeParameterNames($decodedBody);
    }
    $forwardedFor = serverHeaderValue('X-Forwarded-For');
    $forwardedChain = [];
    if ($forwardedFor !== '') {
        foreach (explode(',', $forwardedFor) as $forwardedIp) {
            $forwardedIp = telemetryString($forwardedIp, 100);
            if ($forwardedIp !== '') $forwardedChain[] = $forwardedIp;
        }
    }
    $requestStart = isset($_SERVER['REQUEST_TIME_FLOAT']) ? (float)$_SERVER['REQUEST_TIME_FLOAT'] : (float)($_SERVER['REQUEST_TIME'] ?? time());
    $now = microtime(true);
    $cookieNames = safeParameterNames($_COOKIE);
    $allHeaderNames = [];
    foreach ($_SERVER as $serverKey => $unused) {
        if (strpos($serverKey, 'HTTP_') === 0) {
            $allHeaderNames[] = str_replace('_', '-', substr($serverKey, 5));
        }
    }
    $sessionMeta = sessionTelemetryMetadata();
    $requestKind = (string)($sessionMeta['request_kind'] ?? currentRequestKind());
    $flowId = (string)($sessionMeta['flow_id'] ?? '');
    $reverseDns = getReverseDnsFullData($ip, $ua);
    $networkIdentity = networkIdentityFromGeoData($ip, $countryCode, $ispName, $reverseDns);
    $deviceMemoryTelemetry = deviceMemoryClientHintTelemetry($ua);
    $currentAccept = serverHeaderValue('Accept');
    $initialNavigationHeaders = initialNavigationHeadersTelemetry($requestKind);
    return [
        'ip' => $ip,
        'country' => $countryCode,
        'isp' => $ispName,
        'os' => $currentOS,
        'user_agent' => $ua,
        'referer' => $referer,
        'landing_referer' => $referer,
        'current_request_referer' => $currentRequestReferer,
        'current_request_referer_is_internal_tracker' => refererLooksInternalTracker($currentRequestReferer),
        'query' => $queryString,
        'request_method' => $_SERVER['REQUEST_METHOD'] ?? '',
        'request_kind' => $requestKind,
        'flow_id' => $flowId,
        'network_identity' => $networkIdentity,
        'reverse_dns' => $reverseDns,
        'host' => $_SERVER['HTTP_HOST'] ?? '',
        'https' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
        'content_type' => $_SERVER['CONTENT_TYPE'] ?? '',
        'gate_cookie_received' => isset($_COOKIE['cb_gate_test']),
        'preflight_http_cookie_received' => isset($_COOKIE[$httpGuardCookie]),
        'preflight_js_cookie_received' => isset($_COOKIE[$jsGuardCookie]),
        'accept' => $currentAccept,
        'accept_details' => acceptHeaderTelemetryDetails($currentAccept),
        'initial_navigation_headers' => $initialNavigationHeaders,
        'accept_language' => serverHeaderValue('Accept-Language'),
        'accept_encoding' => serverHeaderValue('Accept-Encoding'),
        'sec_ch_ua' => $_SERVER['HTTP_SEC_CH_UA'] ?? '',
        'sec_ch_ua_mobile' => $_SERVER['HTTP_SEC_CH_UA_MOBILE'] ?? '',
        'sec_ch_ua_platform' => $_SERVER['HTTP_SEC_CH_UA_PLATFORM'] ?? '',
        'sec_fetch_site' => $_SERVER['HTTP_SEC_FETCH_SITE'] ?? '',
        'sec_fetch_mode' => $_SERVER['HTTP_SEC_FETCH_MODE'] ?? '',
        'sec_fetch_dest' => $_SERVER['HTTP_SEC_FETCH_DEST'] ?? '',
        'ja3' => $_SERVER['HTTP_CF_JA3_HASH'] ?? $_SERVER['HTTP_X_JA3'] ?? $_SERVER['HTTP_X_JA3_HASH'] ?? '',
        'request_context' => [
            'request_uri' => $requestUri,
            'path' => telemetryString($requestPath, 2000),
            'protocol' => telemetryString($_SERVER['SERVER_PROTOCOL'] ?? ''),
            'remote_port' => (int)($_SERVER['REMOTE_PORT'] ?? 0),
            'server_port' => (int)($_SERVER['SERVER_PORT'] ?? 0),
            'server_address' => telemetryString($_SERVER['SERVER_ADDR'] ?? ''),
            'server_name' => telemetryString($_SERVER['SERVER_NAME'] ?? ''),
            'scheme' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http',
            'request_time_unix' => $requestStart,
            'request_time_iso8601' => date('c', (int)$requestStart),
            'processing_ms_at_log' => round(max(0, ($now - $requestStart) * 1000), 2),
            'action' => currentFlowAction(),
            'request_kind' => $requestKind,
            'flow_id' => $flowId,
            'page_id' => pageId(),
            'header_count' => count($allHeaderNames),
            'header_names' => array_values(array_unique($allHeaderNames)),
        ],
        'standard_headers' => [
            'content_length' => serverHeaderValue('Content-Length'),
            'origin' => serverHeaderValue('Origin'),
            'connection' => serverHeaderValue('Connection'),
            'cache_control' => serverHeaderValue('Cache-Control'),
            'pragma' => serverHeaderValue('Pragma'),
            'upgrade_insecure_requests' => serverHeaderValue('Upgrade-Insecure-Requests'),
            'dnt' => serverHeaderValue('DNT'),
            'sec_gpc' => serverHeaderValue('Sec-GPC'),
            'sec_fetch_user' => serverHeaderValue('Sec-Fetch-User'),
            'priority' => serverHeaderValue('Priority'),
            'range' => serverHeaderValue('Range'),
            'if_range' => serverHeaderValue('If-Range'),
            'if_none_match' => serverHeaderValue('If-None-Match'),
            'if_modified_since' => serverHeaderValue('If-Modified-Since'),
            'if_match' => serverHeaderValue('If-Match'),
            'if_unmodified_since' => serverHeaderValue('If-Unmodified-Since'),
            'te' => serverHeaderValue('TE'),
            'via' => serverHeaderValue('Via'),
        ],
        'proxy_headers' => [
            'forwarded' => serverHeaderValue('Forwarded'),
            'x_forwarded_for' => $forwardedFor,
            'x_forwarded_for_chain' => $forwardedChain,
            'x_forwarded_for_count' => count($forwardedChain),
            'x_forwarded_proto' => serverHeaderValue('X-Forwarded-Proto'),
            'x_forwarded_host' => serverHeaderValue('X-Forwarded-Host'),
            'x_forwarded_port' => serverHeaderValue('X-Forwarded-Port'),
            'x_real_ip' => serverHeaderValue('X-Real-IP'),
            'cf_connecting_ip' => serverHeaderValue('CF-Connecting-IP'),
            'cdn_loop' => serverHeaderValue('CDN-Loop'),
        ],
        'trace_headers' => [
            'x_request_id' => serverHeaderValue('X-Request-ID'),
            'traceparent' => serverHeaderValue('Traceparent'),
            'tracestate' => serverHeaderValue('Tracestate'),
            'baggage' => serverHeaderValue('Baggage'),
        ],
        'authorization_metadata' => authorizationMetadata($authorization),
        'cookie_metadata' => [
            'count' => count($_COOKIE),
            'names' => $cookieNames,
            'header_length' => strlen($cookieHeader),
            'values_stored' => false,
        ],
        'payload_metadata' => [
            'body_size' => strlen($rawBody),
            'body_sha256' => $rawBody === '' ? '' : hash('sha256', $rawBody),
            'content_type' => $contentType,
            'format' => stripos($contentType, 'json') !== false ? 'json' : (stripos($contentType, 'multipart/form-data') !== false ? 'multipart' : (stripos($contentType, 'application/x-www-form-urlencoded') !== false ? 'form' : ($rawBody === '' ? 'empty' : 'other'))),
            'get_parameter_count' => count($_GET),
            'get_parameter_names' => safeParameterNames($_GET),
            'post_parameter_count' => count($_POST),
            'post_parameter_names' => safeParameterNames($_POST),
            'json_top_level_keys' => $jsonKeys,
            'body_stored' => false,
        ],
        'session_metadata' => $sessionMeta,
        'preflight_metadata' => preflightTelemetryMetadata(),
        'client_hints' => [
            'sec_ch_ua_full_version' => serverHeaderValue('Sec-CH-UA-Full-Version'),
            'sec_ch_ua_full_version_list' => serverHeaderValue('Sec-CH-UA-Full-Version-List'),
            'sec_ch_ua_platform_version' => serverHeaderValue('Sec-CH-UA-Platform-Version'),
            'sec_ch_ua_arch' => serverHeaderValue('Sec-CH-UA-Arch'),
            'sec_ch_ua_bitness' => serverHeaderValue('Sec-CH-UA-Bitness'),
            'sec_ch_ua_wow64' => serverHeaderValue('Sec-CH-UA-WoW64'),
            'sec_ch_ua_model' => serverHeaderValue('Sec-CH-UA-Model'),
            'sec_ch_ua_form_factors' => serverHeaderValue('Sec-CH-UA-Form-Factors'),
            'device_memory' => serverHeaderValue('Device-Memory'),
            'sec_ch_device_memory' => serverHeaderValue('Sec-CH-Device-Memory'),
            'device_memory_details' => $deviceMemoryTelemetry,
            'dpr' => serverHeaderValue('DPR'),
            'width' => serverHeaderValue('Width'),
            'viewport_width' => serverHeaderValue('Viewport-Width'),
            'save_data' => serverHeaderValue('Save-Data'),
            'ect' => serverHeaderValue('ECT'),
            'rtt' => serverHeaderValue('RTT'),
            'downlink' => serverHeaderValue('Downlink'),
        ],
        'response_at_log' => responseMetadataAtLogTime(),
    ];
}

function sanitizeTelemetry($value, $depth = 0) {
    if ($depth > 7) return '[limite de profundidade]';
    if (is_array($value)) {
        $clean = [];
        $count = 0;
        foreach ($value as $key => $item) {
            if ($count++ >= 60) break;
            $clean[substr((string)$key, 0, 80)] = sanitizeTelemetry($item, $depth + 1);
        }
        return $clean;
    }
    if (is_string($value)) return substr($value, 0, 500);
    if (is_bool($value) || is_int($value) || is_float($value) || $value === null) return $value;
    return substr((string)$value, 0, 500);
}

function countRecentFingerprintVisitors($arquivoLog, $fingerprint, $currentVisitorId, $limit = 500) {
    $fingerprint = trim((string)$fingerprint);
    if ($fingerprint === '' || strlen($fingerprint) > 120) return 0;
    $accesses = readJsonFile($arquivoLog, []);
    $visitors = [];
    foreach (array_slice($accesses, 0, $limit) as $access) {
        $clientData = $access['details']['client_data'] ?? [];
        if (!is_array($clientData)) continue;
        $storedFingerprint = (string)($clientData['audioFingerprint'] ?? '');
        $storedVisitor = (string)($clientData['visitorId'] ?? '');
        if ($storedFingerprint === $fingerprint && $storedVisitor !== '' && $storedVisitor !== $currentVisitorId) {
            $visitors[$storedVisitor] = true;
        }
    }
    return count($visitors);
}

function clearOutputBuffers() {
    while (ob_get_level() > 0) {
        $status = ob_get_status();
        $flags = $status['flags'] ?? 0;
        $removableFlag = defined('PHP_OUTPUT_HANDLER_REMOVABLE') ? PHP_OUTPUT_HANDLER_REMOVABLE : 64;
        $isRemovable = (isset($status['flags']) && (($flags & $removableFlag) === $removableFlag)) || (!isset($status['flags']) && !empty($status['del']));
        if (!$isRemovable) {
            break;
        }
        ob_end_clean();
    }
}

function readJsonFile($file, $fallback = []) {
    if (!file_exists($file)) return $fallback;
    $data = json_decode(file_get_contents($file), true);
    return is_array($data) ? $data : $fallback;
}

function writeJsonFile($file, $data) {
    file_put_contents($file, json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
}

function pageId() {
    return md5(($_SERVER['SCRIPT_NAME'] ?? '') . ($_SERVER['SCRIPT_FILENAME'] ?? ''));
}

function clientConfigFingerprint($config) {
    $keys = [
        'lockdown',
        'ips',
        'ua_keywords',
        'os',
        'referers',
        'countries',
        'queries',
        'isps',
        'white_ips',
        'white_ua',
        'white_referers',
        'white_countries',
        'white_queries',
        'white_isps',
        'required_headers_check',
        'accept_language_keywords_check',
        'accept_language_required_keywords',
        'device_memory_header_max_check',
        'device_memory_header_block_min',
        'device_memory_js_max_check',
        'device_memory_js_block_min',
        'auto_bot_signatures',
        'bot_signatures',
        'auto_datacenter',
        'datacenter_keywords',
        'ja3_hashes',
        'preflight_cookie_check',
        'client_min_score',
        'client_check_delay',
        'persistent_session',
        'post_approved_grace_seconds',
        'technical_gate_tolerant_mode',
        'honeypot',
        'resource_check',
        'pow_check',
        'motion_check',
        'gpu_check',
        'vibration_check',
        'action_timing',
        'min_action_ms',
        'headless_extra_check',
        'client_hints_check',
        'cookie_check',
        'pixel_ratio_check',
        'mobile_fonts_check',
        'timezone_check',
        'expected_timezones',
        'network_check',
        'battery_check',
        'device_memory_check',
        'audio_fingerprint_check',
        'storage_check',
        'pointer_check',
        'local_debug_ports_check',
        'whatsapp_deep_link_check'
    ];
    $parts = [];
    foreach ($keys as $key) {
        $parts[$key] = $config[$key] ?? '';
    }
    return substr(md5(json_encode($parts)), 0, 12);
}

function accessUnixTime($access) {
    $stored = $access['details']['server_data']['request_context']['request_time_unix'] ?? null;
    if (is_numeric($stored)) return (float)$stored;
    $date = DateTime::createFromFormat('d/m/Y H:i:s', (string)($access['data_hora'] ?? ''));
    return $date ? (float)$date->getTimestamp() : 0;
}


function httpMethodBucket($method) {
    $method = strtoupper(trim((string)$method));
    return in_array($method, ['GET', 'POST', 'HEAD'], true) ? $method : 'OTHER';
}

function pathLooksSensitive($path) {
    return preg_match('~(?:^|/)(?:\.env|\.git|wp-admin|wp-login\.php|phpmyadmin|server-status)(?:/|$)~i', (string)$path) === 1;
}

function populationStdDev($values) {
    $count = count($values);
    if ($count < 2) return null;
    $mean = array_sum($values) / $count;
    $variance = 0.0;
    foreach ($values as $value) {
        $delta = (float)$value - $mean;
        $variance += $delta * $delta;
    }
    return sqrt($variance / $count);
}

function safeRatio($part, $total) {
    $total = (int)$total;
    if ($total <= 0) return 0;
    return round(((int)$part / $total) * 100, 2);
}

function requestShapeFromServerData($serverData) {
    $payload = $serverData['payload_metadata'] ?? [];
    if (!is_array($payload)) $payload = [];

    $getNames = $payload['get_parameter_names'] ?? [];
    $postNames = $payload['post_parameter_names'] ?? [];
    $jsonKeys = $payload['json_top_level_keys'] ?? [];
    if (!is_array($getNames)) $getNames = [];
    if (!is_array($postNames)) $postNames = [];
    if (!is_array($jsonKeys)) $jsonKeys = [];

    sort($getNames);
    sort($postNames);
    sort($jsonKeys);

    $shape = [
        'method' => httpMethodBucket($serverData['request_method'] ?? 'GET'),
        'request_kind' => (string)($serverData['request_kind'] ?? ($serverData['request_context']['request_kind'] ?? '')),
        'path' => (string)($serverData['request_context']['path'] ?? ''),
        'content_type' => (string)($payload['content_type'] ?? ''),
        'format' => (string)($payload['format'] ?? ''),
        'get_names' => array_values($getNames),
        'post_names' => array_values($postNames),
        'json_keys' => array_values($jsonKeys),
    ];

    return [
        'hash' => substr(hash('sha256', json_encode($shape, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)), 0, 24),
        'shape' => $shape,
    ];
}

function buildServerHistory($accesses, $ip, $countryCode, $ispName, $ua, $traceId, $serverData) {
    $now = (float)($serverData['request_context']['request_time_unix'] ?? microtime(true));
    $sessionHash = (string)($serverData['session_metadata']['id_hash'] ?? '');
    $path = (string)($serverData['request_context']['path'] ?? '');
    $method = strtoupper((string)($serverData['request_method'] ?? 'GET'));
    $currentMethodBucket = httpMethodBucket($method);
    $currentBodyHash = (string)($serverData['payload_metadata']['body_sha256'] ?? '');
    $currentShape = requestShapeFromServerData($serverData);
    $currentShapeHash = (string)($currentShape['hash'] ?? '');
    $currentRequestKind = (string)($serverData['request_kind'] ?? ($serverData['request_context']['request_kind'] ?? ''));
    $currentFlowId = (string)($serverData['flow_id'] ?? ($serverData['session_metadata']['flow_id'] ?? ''));

    $sameIp = 0;
    $sameSession = 0;
    $blocked = 0;
    $pending = 0;
    $allowed = 0;
    $unfinishedGate = 0;
    $recent60 = 0;
    $recent300 = 0;
    $recent3600 = 0;
    $sameSecond = 0;
    $lastTimestamp = 0;

    $methodsSameIp = ['GET' => 0, 'POST' => 0, 'HEAD' => 0, 'OTHER' => 0];
    $methodsSameSession = ['GET' => 0, 'POST' => 0, 'HEAD' => 0, 'OTHER' => 0];
    $methodsSameIpLast60 = ['GET' => 0, 'POST' => 0, 'HEAD' => 0, 'OTHER' => 0];
    $methodsSameIpLast300 = ['GET' => 0, 'POST' => 0, 'HEAD' => 0, 'OTHER' => 0];
    $methodsSameIpLast3600 = ['GET' => 0, 'POST' => 0, 'HEAD' => 0, 'OTHER' => 0];

    $userAgents = [];
    $countries = [];
    $isps = [];
    $sessionIps = [];
    $uniqueSessionsSameIp = [];
    $pathSequence = [];
    $methodPathSequence = [];
    $sameSessionGetBeforeCurrent = 0;
    $sameSessionPostBeforeCurrent = 0;
    $sensitiveHitsSameIp = 0;
    $sensitiveHitsSameSession = 0;

    $sameUaIps = [];
    $sameUaIpsLastHour = [];
    $sameUaSessions = [];
    $sameUaTotal = 0;

    $bodyHashRepeatsTotal = 0;
    $bodyHashRepeatsSameIp = 0;
    $bodyHashIps = [];
    $bodyHashSessions = [];
    $bodyHashRepeatsLastHour = 0;

    $shapeRepeatsTotal = 0;
    $shapeRepeatsSameIp = 0;
    $shapeIps = [];
    $shapeSessions = [];

    $sameFlowPreviousTotal = 0;
    $sameFlowMethodCounts = ['GET' => 0, 'POST' => 0, 'HEAD' => 0, 'OTHER' => 0];
    $sameFlowRequestKinds = [];
    $sameFlowSequence = [];
    $sameFlowTimes = [];
    if ($currentFlowId !== '' && $now > 0) {
        $sameFlowTimes[] = $now;
    }

    $sameIpSameSessionTimes = [];
    if ($ip !== '' && $sessionHash !== '' && $now > 0) {
        $sameIpSameSessionTimes[] = $now;
    }

    foreach (array_slice($accesses, 0, 2000) as $access) {
        if ($traceId !== '' && ($access['details']['trace_id'] ?? '') === $traceId) continue;

        $storedServerData = $access['details']['server_data'] ?? [];
        if (!is_array($storedServerData)) $storedServerData = [];

        $storedIp = (string)($access['ip'] ?? '');
        $storedSession = (string)($storedServerData['session_metadata']['id_hash'] ?? '');
        $storedTime = accessUnixTime($access);
        $age = $storedTime > 0 ? max(0, $now - $storedTime) : PHP_INT_MAX;
        $storedMethod = strtoupper((string)($storedServerData['request_method'] ?? 'GET'));
        $storedMethodBucket = httpMethodBucket($storedMethod);
        $storedPath = (string)($storedServerData['request_context']['path'] ?? '');
        $storedAction = (string)($storedServerData['request_context']['action'] ?? '');
        $storedUa = telemetryString($access['ua'] ?? '', 500);
        $storedCountry = telemetryString($access['country'] ?? '', 20);
        $storedIsp = telemetryString($access['isp'] ?? '', 300);
        $storedBodyHash = (string)($storedServerData['payload_metadata']['body_sha256'] ?? '');
        $storedShape = requestShapeFromServerData($storedServerData);
        $storedShapeHash = (string)($storedShape['hash'] ?? '');
        $storedRequestKind = (string)($storedServerData['request_kind'] ?? ($storedServerData['request_context']['request_kind'] ?? ''));
        $storedFlowId = (string)($storedServerData['flow_id'] ?? ($storedServerData['session_metadata']['flow_id'] ?? ''));

        if ($ua !== '' && $storedUa === $ua) {
            $sameUaTotal++;
            if ($storedIp !== '') $sameUaIps[$storedIp] = true;
            if ($age <= 3600 && $storedIp !== '') $sameUaIpsLastHour[$storedIp] = true;
            if ($storedSession !== '') $sameUaSessions[$storedSession] = true;
        }

        if ($currentBodyHash !== '' && $storedBodyHash === $currentBodyHash) {
            $bodyHashRepeatsTotal++;
            if ($storedIp !== '') $bodyHashIps[$storedIp] = true;
            if ($storedSession !== '') $bodyHashSessions[$storedSession] = true;
            if ($age <= 3600) $bodyHashRepeatsLastHour++;
        }

        if ($currentShapeHash !== '' && $storedShapeHash === $currentShapeHash) {
            $shapeRepeatsTotal++;
            if ($storedIp !== '') $shapeIps[$storedIp] = true;
            if ($storedSession !== '') $shapeSessions[$storedSession] = true;
        }


        if ($currentFlowId !== '' && $storedFlowId === $currentFlowId) {
            $sameFlowPreviousTotal++;
            $sameFlowMethodCounts[$storedMethodBucket]++;
            if ($storedRequestKind !== '') $sameFlowRequestKinds[$storedRequestKind] = true;
            if ($storedTime > 0) $sameFlowTimes[] = $storedTime;
            if (count($sameFlowSequence) < 25) {
                $sameFlowSequence[] = [
                    'method' => $storedMethodBucket,
                    'kind' => telemetryString($storedRequestKind, 120),
                    'path' => telemetryString($storedPath, 2000),
                    'action' => telemetryString($storedAction, 120),
                    'age_seconds' => $age === PHP_INT_MAX ? null : round($age, 3),
                ];
            }
        }

        if ($sessionHash !== '' && $storedSession === $sessionHash) {
            $sameSession++;
            $methodsSameSession[$storedMethodBucket]++;
            if ($storedMethodBucket === 'GET') $sameSessionGetBeforeCurrent++;
            if ($storedMethodBucket === 'POST') $sameSessionPostBeforeCurrent++;
            if ($storedIp !== '') $sessionIps[$storedIp] = true;
            if (pathLooksSensitive($storedPath)) $sensitiveHitsSameSession++;
        }

        if ($storedIp !== $ip) continue;

        $sameIp++;
        $methodsSameIp[$storedMethodBucket]++;
        if ($age <= 60) $methodsSameIpLast60[$storedMethodBucket]++;
        if ($age <= 300) $methodsSameIpLast300[$storedMethodBucket]++;
        if ($age <= 3600) $methodsSameIpLast3600[$storedMethodBucket]++;
        if ($storedSession !== '') $uniqueSessionsSameIp[$storedSession] = true;
        if ($currentBodyHash !== '' && $storedBodyHash === $currentBodyHash) $bodyHashRepeatsSameIp++;
        if ($currentShapeHash !== '' && $storedShapeHash === $currentShapeHash) $shapeRepeatsSameIp++;
        if ($sessionHash !== '' && $storedSession === $sessionHash && $storedTime > 0) $sameIpSameSessionTimes[] = $storedTime;
        if (pathLooksSensitive($storedPath)) $sensitiveHitsSameIp++;

        $reason = (string)($access['reason'] ?? '');
        if (stripos($reason, 'BLOCKED') !== false) $blocked++;
        if (stripos($reason, 'PENDING') !== false) $pending++;
        if (stripos($reason, 'ALLOWED') !== false) $allowed++;
        if (stripos($reason, 'Aguardando gate client-side') !== false) $unfinishedGate++;
        if ($age <= 60) $recent60++;
        if ($age <= 300) $recent300++;
        if ($age <= 3600) $recent3600++;
        if ($age < 1) $sameSecond++;
        if ($storedTime > $lastTimestamp) $lastTimestamp = $storedTime;

        if ($storedUa !== '') $userAgents[$storedUa] = true;
        if ($storedCountry !== '') $countries[$storedCountry] = true;
        if ($storedIsp !== '') $isps[$storedIsp] = true;
        if (count($pathSequence) < 10 && $storedPath !== '') {
            $pathSequence[] = $storedPath;
        }
        if (count($methodPathSequence) < 15 && $storedPath !== '') {
            $methodPathSequence[] = [
                'method' => $storedMethodBucket,
                'path' => telemetryString($storedPath, 2000),
                'action' => telemetryString($storedAction, 120),
                'age_seconds' => $age === PHP_INT_MAX ? null : round($age, 3),
            ];
        }
    }

    $sensitivePath = pathLooksSensitive($path);
    $unusualMethod = !in_array($method, ['GET', 'POST', 'HEAD'], true);
    $currentUaSeen = $ua !== '' && isset($userAgents[$ua]);
    $currentCountrySeen = $countryCode !== '' && isset($countries[$countryCode]);
    $currentIspSeen = $ispName !== '' && isset($isps[$ispName]);
    if ($sessionHash !== '' && $ip !== '') $sessionIps[$ip] = true;
    if ($sessionHash !== '') $uniqueSessionsSameIp[$sessionHash] = true;
    array_unshift($pathSequence, $path);
    array_unshift($methodPathSequence, [
        'method' => $currentMethodBucket,
        'path' => telemetryString($path, 2000),
        'action' => telemetryString($serverData['request_context']['action'] ?? '', 120),
        'age_seconds' => 0,
    ]);

    $methodCountsSameIpIncludingCurrent = $methodsSameIp;
    $methodCountsSameIpIncludingCurrent[$currentMethodBucket]++;
    $methodCountsSameSessionIncludingCurrent = $methodsSameSession;
    $methodCountsSameSessionIncludingCurrent[$currentMethodBucket]++;

    sort($sameIpSameSessionTimes, SORT_NUMERIC);
    $cadenceIntervalsMs = [];
    for ($i = 1; $i < count($sameIpSameSessionTimes); $i++) {
        $gapMs = round(max(0, ($sameIpSameSessionTimes[$i] - $sameIpSameSessionTimes[$i - 1]) * 1000), 2);
        $cadenceIntervalsMs[] = $gapMs;
    }
    $cadenceStdDev = populationStdDev($cadenceIntervalsMs);
    $cadenceMean = count($cadenceIntervalsMs) > 0 ? round(array_sum($cadenceIntervalsMs) / count($cadenceIntervalsMs), 2) : null;
    $cadenceMin = count($cadenceIntervalsMs) > 0 ? min($cadenceIntervalsMs) : null;
    $cadenceMax = count($cadenceIntervalsMs) > 0 ? max($cadenceIntervalsMs) : null;
    $cadenceSample = array_slice($cadenceIntervalsMs, -12);

    $sameFlowMethodCountsIncludingCurrent = $sameFlowMethodCounts;
    $sameFlowMethodCountsIncludingCurrent[$currentMethodBucket]++;
    if ($currentRequestKind !== '') $sameFlowRequestKinds[$currentRequestKind] = true;
    array_unshift($sameFlowSequence, [
        'method' => $currentMethodBucket,
        'kind' => telemetryString($currentRequestKind, 120),
        'path' => telemetryString($path, 2000),
        'action' => telemetryString($serverData['request_context']['action'] ?? '', 120),
        'age_seconds' => 0,
    ]);
    $sameFlowTimingStats = timingStatsFromTimestamps($sameFlowTimes);

    return [
        'previous_same_ip_total' => $sameIp,
        'previous_same_session_total' => $sameSession,
        'previous_blocks_same_ip' => $blocked,
        'previous_pending_same_ip' => $pending,
        'previous_allowed_same_ip' => $allowed,
        'previous_unfinished_gates_same_ip' => $unfinishedGate,
        'requests_same_ip_last_60_seconds' => $recent60,
        'requests_same_ip_last_5_minutes' => $recent300,
        'requests_same_ip_last_hour' => $recent3600,
        'requests_same_ip_within_one_second' => $sameSecond,
        'seconds_since_previous_same_ip' => $lastTimestamp > 0 ? round(max(0, $now - $lastTimestamp), 3) : null,

        'previous_get_same_ip_total' => $methodsSameIp['GET'],
        'previous_post_same_ip_total' => $methodsSameIp['POST'],
        'previous_head_same_ip_total' => $methodsSameIp['HEAD'],
        'previous_other_methods_same_ip_total' => $methodsSameIp['OTHER'],
        'previous_get_same_session_total' => $methodsSameSession['GET'],
        'previous_post_same_session_total' => $methodsSameSession['POST'],
        'previous_head_same_session_total' => $methodsSameSession['HEAD'],
        'previous_other_methods_same_session_total' => $methodsSameSession['OTHER'],

        'method_counts_same_ip' => $methodsSameIp,
        'method_counts_same_ip_including_current' => $methodCountsSameIpIncludingCurrent,
        'method_counts_same_session' => $methodsSameSession,
        'method_counts_same_session_including_current' => $methodCountsSameSessionIncludingCurrent,
        'method_counts_same_ip_last_60_seconds' => $methodsSameIpLast60,
        'method_counts_same_ip_last_5_minutes' => $methodsSameIpLast300,
        'method_counts_same_ip_last_hour' => $methodsSameIpLast3600,
        'current_request_method_bucket' => $currentMethodBucket,
        'current_request_kind' => $currentRequestKind,
        'current_flow_id' => $currentFlowId,
        'post_without_prior_get_same_session' => $currentMethodBucket === 'POST' && $sameSessionGetBeforeCurrent <= 0,

        'unique_user_agents_same_ip' => count($userAgents),
        'unique_countries_same_ip' => count($countries),
        'unique_isps_same_ip' => count($isps),
        'unique_ips_same_session' => count($sessionIps),
        'unique_sessions_same_ip' => count($uniqueSessionsSameIp),
        'user_agent_changed_for_ip' => $sameIp > 0 && !$currentUaSeen,
        'country_changed_for_ip' => $sameIp > 0 && !$currentCountrySeen,
        'isp_changed_for_ip' => $sameIp > 0 && !$currentIspSeen,

        'same_user_agent_reuse' => [
            'previous_total_same_ua' => $sameUaTotal,
            'distinct_ips_same_ua' => count($sameUaIps),
            'distinct_ips_same_ua_last_hour' => count($sameUaIpsLastHour),
            'distinct_sessions_same_ua' => count($sameUaSessions),
            'seen_from_other_ips' => count(array_diff(array_keys($sameUaIps), [$ip])) > 0,
        ],

        'payload_reuse' => [
            'body_hash_present' => $currentBodyHash !== '',
            'same_body_hash_previous_total' => $bodyHashRepeatsTotal,
            'same_body_hash_previous_same_ip' => $bodyHashRepeatsSameIp,
            'same_body_hash_previous_last_hour' => $bodyHashRepeatsLastHour,
            'distinct_ips_same_body_hash' => count($bodyHashIps),
            'distinct_sessions_same_body_hash' => count($bodyHashSessions),
            'request_shape_hash' => $currentShapeHash,
            'request_shape' => $currentShape['shape'] ?? [],
            'same_request_shape_previous_total' => $shapeRepeatsTotal,
            'same_request_shape_previous_same_ip' => $shapeRepeatsSameIp,
            'distinct_ips_same_request_shape' => count($shapeIps),
            'distinct_sessions_same_request_shape' => count($shapeSessions),
        ],

        'behavior_rates_same_ip' => [
            'block_rate_percent' => safeRatio($blocked, $sameIp),
            'pending_rate_percent' => safeRatio($pending, $sameIp),
            'allowed_rate_percent' => safeRatio($allowed, $sameIp),
            'unfinished_gate_rate_percent' => safeRatio($unfinishedGate, $sameIp),
            'post_rate_percent' => safeRatio($methodsSameIp['POST'], max(1, array_sum($methodsSameIp))),
            'get_rate_percent' => safeRatio($methodsSameIp['GET'], max(1, array_sum($methodsSameIp))),
        ],

        'sensitive_paths' => [
            'current_path_sensitive' => $sensitivePath,
            'previous_sensitive_path_hits_same_ip' => $sensitiveHitsSameIp,
            'previous_sensitive_path_hits_same_session' => $sensitiveHitsSameSession,
            'sensitive_path_hit_including_current_same_ip' => $sensitiveHitsSameIp + ($sensitivePath ? 1 : 0),
        ],


        'flow_history' => [
            'flow_id' => $currentFlowId,
            'previous_requests_same_flow' => $sameFlowPreviousTotal,
            'method_counts_same_flow_previous' => $sameFlowMethodCounts,
            'method_counts_same_flow_including_current' => $sameFlowMethodCountsIncludingCurrent,
            'request_kinds_seen_same_flow' => array_keys($sameFlowRequestKinds),
            'timing_stats_same_flow' => $sameFlowTimingStats,
            'recent_sequence_same_flow' => $sameFlowSequence,
            'informational_only' => true,
        ],

        'time_cadence_entropy' => [
            'description' => 'Desvio padrao dos intervalos entre requisicoes sequenciais do mesmo IP na mesma sessao.',
            'sample_scope' => 'same_ip_and_same_session_including_current',
            'request_points_count' => count($sameIpSameSessionTimes),
            'interval_count' => count($cadenceIntervalsMs),
            'mean_interval_ms' => $cadenceMean,
            'stddev_interval_ms' => $cadenceStdDev === null ? null : round($cadenceStdDev, 2),
            'min_interval_ms' => $cadenceMin,
            'max_interval_ms' => $cadenceMax,
            'recent_interval_sample_ms' => $cadenceSample,
            'mechanical_cadence_suspected' => count($cadenceIntervalsMs) >= 3 && $cadenceStdDev !== null && $cadenceStdDev <= 150,
            'mechanical_cadence_rule' => 'Informativo: true quando ha pelo menos 3 intervalos e desvio padrao <= 150 ms.',
        ],

        'unusual_http_method' => $unusualMethod,
        'sensitive_path_pattern' => $sensitivePath,
        'recent_path_sequence' => array_values(array_filter($pathSequence)),
        'recent_method_path_sequence' => $methodPathSequence,
        'informational_only' => true,
    ];
}

function appendAccessLog($arquivoLog, $ip, $countryCode, $ispName, $currentOS, $status, $ua, $referer, $queryString, $details = []) {
    $pageID = pageId();
    $sessionKeyIP = 'last_log_ip_' . $pageID;
    $sessionKeyTime = 'last_log_time_' . $pageID;
    $sessionKeyStatus = 'last_status_' . $pageID;
    if (!is_array($details)) $details = [];
    $traceId = (string)($details['trace_id'] ?? ($_SESSION['active_access_trace_' . $pageID] ?? ''));
    $traceId = preg_match('/^[a-f0-9]{32}$/', $traceId) ? $traceId : '';
    if ($traceId !== '') $details['trace_id'] = $traceId;

    if ($traceId === '' && isset($_SESSION[$sessionKeyIP]) && $_SESSION[$sessionKeyIP] === $ip &&
        isset($_SESSION[$sessionKeyTime]) && (time() - $_SESSION[$sessionKeyTime] < 2) &&
        isset($_SESSION[$sessionKeyStatus]) && $_SESSION[$sessionKeyStatus] === $status) {
        return;
    }

    $handle = fopen($arquivoLog, 'c+');
    if (!$handle) return;
    if (!flock($handle, LOCK_EX)) {
        fclose($handle);
        return;
    }

    rewind($handle);
    $contents = stream_get_contents($handle);
    $dadosAtuais = json_decode($contents, true);
    if (!is_array($dadosAtuais)) $dadosAtuais = [];
    if (isset($details['server_data']) && is_array($details['server_data'])) {
        $activeConfig = isset($GLOBALS['config']) && is_array($GLOBALS['config']) ? $GLOBALS['config'] : [];
        $isBlockedStatus = stripos($status, 'BLOCKED') !== false;
        $isPendingStatus = stripos($status, 'PENDING') !== false;
        $isAllowedStatus = stripos($status, 'ALLOWED') !== false;
        $details['server_data']['history'] = buildServerHistory($dadosAtuais, $ip, $countryCode, $ispName, $ua, $traceId, $details['server_data']);
        $details['server_data']['decision_at_log'] = [
            'status_text' => $status,
            'blocked' => $isBlockedStatus,
            'pending' => $isPendingStatus,
            'allowed' => $isAllowedStatus,
            'expected_response' => $isAllowedStatus ? 'protected_content' : ($isPendingStatus ? 'validation_response' : 'blocked_response'),
            'configured_block_mode' => $isBlockedStatus ? 'neutral_403' : '',
            'configured_block_target' => '',
        ];
    }
    $nextId = 1;
    $existingIndex = null;
    foreach ($dadosAtuais as $existingAccess) {
        $nextId = max($nextId, ((int)($existingAccess['row'] ?? 0)) + 1);
    }
    if ($traceId !== '') {
        foreach ($dadosAtuais as $index => $existingAccess) {
            if (($existingAccess['details']['trace_id'] ?? '') === $traceId) {
                $existingIndex = $index;
                break;
            }
        }
    }

    if ($existingIndex !== null) {
        $previousReferer = (string)($dadosAtuais[$existingIndex]['referer'] ?? '');
        if ($previousReferer !== '' && $previousReferer !== 'Direto' && !refererLooksInternalTracker($previousReferer) && ($referer === '' || $referer === 'Direto' || refererLooksInternalTracker($referer))) {
            $referer = $previousReferer;
        }
    }
    $referer = $referer === '' ? 'Direto' : telemetryString($referer, 2000);
    if (isset($details['server_data']) && is_array($details['server_data'])) {
        $details['server_data']['referer'] = $referer;
        $details['server_data']['landing_referer'] = $referer;
    }

    $novoAcesso = [
        'row' => $existingIndex === null ? $nextId : (int)($dadosAtuais[$existingIndex]['row'] ?? $nextId),
        'data_hora' => $existingIndex === null ? date('d/m/Y H:i:s') : ($dadosAtuais[$existingIndex]['data_hora'] ?? date('d/m/Y H:i:s')),
        'atualizado_em' => date('d/m/Y H:i:s'),
        'ip' => $ip,
        'country' => $countryCode,
        'isp' => $ispName,
        'os' => $currentOS,
        'reason' => $status,
        'ua' => $ua,
        'referer' => $referer,
        'query' => $queryString,
        'details' => $details,
    ];

    if ($existingIndex !== null) array_splice($dadosAtuais, $existingIndex, 1);
    array_unshift($dadosAtuais, $novoAcesso);
    if (count($dadosAtuais) > 2000) $dadosAtuais = array_slice($dadosAtuais, 0, 2000);
    rewind($handle);
    ftruncate($handle, 0);
    fwrite($handle, json_encode($dadosAtuais, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    fflush($handle);
    flock($handle, LOCK_UN);
    fclose($handle);

    $_SESSION[$sessionKeyIP] = $ip;
    $_SESSION[$sessionKeyTime] = time();
    $_SESSION[$sessionKeyStatus] = $status;
}

function getActionUrl($action, $extra = []) {
    $path = $_SERVER['SCRIPT_NAME'] ?? '';
    $params = array_merge(['flow_action' => normalizeFlowAction($action)], $extra);
    return $path . '?' . http_build_query($params);
}

function currentRequestTarget($removeParams = [], $addParams = []) {
    $requestUri = str_replace(["\r", "\n"], '', (string)($_SERVER['REQUEST_URI'] ?? ''));
    $path = parse_url($requestUri, PHP_URL_PATH);
    if (!is_string($path) || $path === '') $path = $_SERVER['SCRIPT_NAME'] ?? '/';
    $params = [];
    $query = parse_url($requestUri, PHP_URL_QUERY);
    if (is_string($query) && $query !== '') parse_str($query, $params);
    foreach ($removeParams as $key) unset($params[$key]);
    foreach ($addParams as $key => $value) $params[$key] = $value;
    return $path . (empty($params) ? '' : '?' . http_build_query($params));
}

function sendEmptyRedirect($target) {
    clearOutputBuffers();
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('X-Robots-Tag: noindex, nofollow, noarchive');
    header('Location: ' . $target, true, 302);
    header('Content-Length: 0');
    exit;
}

function sendEmptyForbidden() {
    clearOutputBuffers();
    http_response_code(403);
    header('Connection: close');
    header('Content-Length: 0');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('X-Robots-Tag: noindex, nofollow, noarchive');
    exit;
}

function setGuardCookie($name, $value, $httpOnly, $expires) {
    setcookie($name, $value, [
        'expires' => $expires,
        'path' => '/',
        'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        'httponly' => (bool)$httpOnly,
        'samesite' => 'Lax',
    ]);
}

function guardCookieNames($pageID) {
    $suffix = substr($pageID, 0, 10);
    return ['site_http_' . $suffix, 'site_js_' . $suffix];
}

function sendJavascriptBootstrap($cookieName, $token, $target) {
    $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? '; Secure' : '';
    $cookieValue = $cookieName . '=' . $token . '; Path=/; Max-Age=300; SameSite=Lax' . $secure;
    clearOutputBuffers();
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('X-Robots-Tag: noindex, nofollow, noarchive');
    header("Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'");
    header('Referrer-Policy: no-referrer');
    header('X-Content-Type-Options: nosniff');
    echo '<!doctype html><meta charset="utf-8"><meta name="robots" content="noindex,nofollow,noarchive"><script>document.cookie=' . json_encode($cookieValue) . ';location.replace(' . json_encode($target) . ');</script>';
    exit;
}

function clearAccessAttemptState($pageID, $scope) {
    $activeScope = (string)($_SESSION['active_access_scope_' . $pageID] ?? '');
    foreach (array_unique(array_filter([$scope, $activeScope])) as $scopeKey) {
        unset(
            $_SESSION['preflight_http_hash_' . $scopeKey],
            $_SESSION['preflight_http_ok_' . $scopeKey],
            $_SESSION['preflight_js_hash_' . $scopeKey],
            $_SESSION['preflight_js_ok_' . $scopeKey],
            $_SESSION['preflight_attempt_started_' . $scopeKey],
            $_SESSION['preflight_http_issued_' . $scopeKey],
            $_SESSION['preflight_http_completed_' . $scopeKey],
            $_SESSION['preflight_js_issued_' . $scopeKey],
            $_SESSION['preflight_js_completed_' . $scopeKey],
            $_SESSION['render_verified_' . $scopeKey],
            $_SESSION['render_signals_' . $scopeKey],
            $_SESSION['render_checks_' . $scopeKey],
            $_SESSION['render_gate_info_' . $scopeKey],
            $_SESSION['landing_referer_' . $scopeKey],
            $_SESSION['current_request_referer_' . $scopeKey],
            $_SESSION[gateFlowKey($scopeKey)],
            $_SESSION['client_verified_grace_until_' . $scopeKey]
        );
    }
    unset(
        $_SESSION['active_access_scope_' . $pageID],
        $_SESSION['active_access_trace_' . $pageID],
        $_SESSION['access_pending_logged_' . $pageID],
        $_SESSION['challenge_nonce_' . $pageID],
        $_SESSION['server_checks_' . $pageID]
    );
}

function expireGuardCookies($pageID) {
    foreach (guardCookieNames($pageID) as $cookieName) {
        setGuardCookie($cookieName, '', false, time() - 3600);
    }
}

function gateFlowKey($scope) {
    return 'gate_flow_progress_' . md5((string)$scope);
}

function flowStepSeen($progress, $step) {
    if (!is_array($progress) || empty($progress['steps']) || !is_array($progress['steps'])) return false;
    foreach ($progress['steps'] as $entry) {
        if (is_array($entry) && (string)($entry['step'] ?? '') === $step) return true;
    }
    return false;
}

function gateFlowPostExecution($progress) {
    if (!is_array($progress)) return ['validation_post_received' => false, 'diagnostic_post_received' => false, 'post_stage' => '', 'summary' => 'Sem diagnostico de fluxo'];
    $steps = isset($progress['steps']) && is_array($progress['steps']) ? $progress['steps'] : [];
    $validationPostSteps = ['view_state_received', 'session_sync_received', 'session_event_received'];
    $diagnosticOnlySteps = ['page_hidden', 'page_visible', 'pagehide', 'beforeunload', 'freeze', 'blur', 'bootstrap_started', 'render_collection_started', 'client_collection_started'];
    $seen = [];
    $diagnosticSeen = [];
    foreach ($steps as $entry) {
        if (!is_array($entry)) continue;
        $st = (string)($entry['step'] ?? '');
        if (in_array($st, $validationPostSteps, true)) $seen[] = $st;
        if (in_array($st, $diagnosticOnlySteps, true)) $diagnosticSeen[] = $st;
    }
    if (!empty($seen)) {
        return [
            'validation_post_received' => true,
            'diagnostic_post_received' => !empty($diagnosticSeen),
            'post_stage' => end($seen),
            'summary' => 'Houve POST de validacao do navegador no fluxo client-side',
            'validation_post_steps_seen' => $seen,
            'diagnostic_post_steps_seen' => $diagnosticSeen,
        ];
    }
    $last = (string)($progress['last_step'] ?? '');
    $summary = !empty($diagnosticSeen) ? 'Chegou POST apenas de diagnostico/progresso; nenhum POST de validacao chegou' : 'Nenhum POST client-side recebido ate o ultimo registro';
    if (flowStepSeen($progress, 'base_asset_delivered')) {
        $summary = 'stage1_code/base_asset foi entregue, mas nenhum POST render_check/view_state ou session_sync chegou';
    } elseif (flowStepSeen($progress, 'base_asset_requested')) {
        $summary = 'stage1_code/base_asset foi solicitado, mas nenhum POST de validacao chegou';
    } elseif (flowStepSeen($progress, 'initial_page_sent')) {
        $summary = !empty($diagnosticSeen) ? 'HTML inicial entregue; houve POST de diagnostico, mas nenhum POST de validacao' : 'HTML inicial entregue; nenhum POST e nenhum progresso conclusivo de JS';
    }
    return ['validation_post_received' => false, 'diagnostic_post_received' => !empty($diagnosticSeen), 'post_stage' => '', 'last_step' => $last, 'summary' => $summary, 'diagnostic_post_steps_seen' => $diagnosticSeen];
}

function classifyGateFlowProgress($progress) {
    if (!is_array($progress)) return ['code' => 'SEM_DIAGNOSTICO', 'label' => 'Sem diagnostico de fluxo', 'likely' => 'desconhecido'];
    $last = (string)($progress['last_step'] ?? '');
    $post = gateFlowPostExecution($progress);
    $code = 'EM_ANDAMENTO';
    $label = 'Fluxo em andamento ou interrompido sem classificacao final';
    $likely = 'indefinido';

    if ($last === 'approved' || flowStepSeen($progress, 'approved')) {
        $code = 'GATE_COMPLETO'; $label = 'Gate completo aprovado'; $likely = 'humano/navegador completo';
    } elseif ($last === 'blocked' || flowStepSeen($progress, 'blocked')) {
        $code = 'GATE_BLOQUEADO'; $label = 'Gate completo bloqueado por filtro ativo'; $likely = 'bloqueado por regra';
    } elseif (in_array($last, ['page_hidden','pagehide','beforeunload','freeze','blur'], true)) {
        $prev = '';
        $steps = isset($progress['steps']) && is_array($progress['steps']) ? $progress['steps'] : [];
        for ($i = count($steps) - 2; $i >= 0; $i--) {
            $candidate = (string)($steps[$i]['step'] ?? '');
            if (!in_array($candidate, ['page_hidden','page_visible','pagehide','beforeunload','freeze','blur'], true)) { $prev = $candidate; break; }
        }
        $code = 'PAGINA_OCULTA_' . strtoupper($prev ?: 'SEM_ETAPA');
        $label = 'Pagina ficou oculta durante o fluxo; ultimo passo util: ' . ($prev ?: 'nao identificado');
        $likely = 'WebView/app em background, usuario saiu, ou automacao interrompida';
    } elseif (empty($post['validation_post_received']) && flowStepSeen($progress, 'initial_page_sent') && !flowStepSeen($progress, 'base_asset_requested')) {
        $code = 'HTML_SEM_STAGE1'; $label = 'HTML inicial entregue, mas stage1_code/base_asset nao foi solicitado'; $likely = 'bot/preview so GET, usuario saiu rapido ou JS nao executou';
    } elseif (empty($post['validation_post_received']) && flowStepSeen($progress, 'base_asset_delivered') && !flowStepSeen($progress, 'render_check_post_started')) {
        $code = 'STAGE1_SEM_RENDER_POST'; $label = 'stage1_code/base_asset entregue, mas render_check/view_state nao foi postado'; $likely = 'JS interrompido, coleta render travou, pagina saiu de foco ou automacao parcial';
    } elseif (flowStepSeen($progress, 'render_collection_started') && !flowStepSeen($progress, 'render_collection_finished')) {
        $code = 'RENDER_INICIOU_SEM_FINALIZAR'; $label = 'Render Signals iniciou, mas nao finalizou'; $likely = 'pagina suspensa/interrompida ou coleta demorou/travou';
    } elseif (flowStepSeen($progress, 'render_collection_finished') && !flowStepSeen($progress, 'view_state_received')) {
        $code = 'RENDER_COLETADO_SEM_POST'; $label = 'Render Signals coletado, mas POST render_check/view_state nao chegou'; $likely = 'fetch cancelado, rede/WebView, pagehide ou bloqueio de transporte';
    } elseif (flowStepSeen($progress, 'view_state_passed') && !flowStepSeen($progress, 'runtime_asset_delivered')) {
        $code = 'RENDER_OK_SEM_STAGE2'; $label = 'render_check/view_state aprovado, mas stage2_code/runtime_asset nao concluiu'; $likely = 'fetch do stage2 cancelado ou sessao/estado expirado';
    } elseif (flowStepSeen($progress, 'runtime_asset_delivered') && !flowStepSeen($progress, 'session_sync_received')) {
        $code = 'STAGE2_SEM_SESSION_SYNC'; $label = 'stage2_code/runtime_asset entregue, mas client_check/session_sync nao chegou'; $likely = 'segunda coleta interrompida, pagehide ou fetch final cancelado';
    } elseif ($last === 'session_event_received') {
        $code = 'FALHA_TECNICA_REPORTADA'; $label = 'Navegador reportou falha tecnica do gate'; $likely = 'erro de transporte/JSON/execucao reportado pelo JS';
    }
    return ['code' => $code, 'label' => $label, 'likely' => $likely, 'post_execution' => $post, 'last_step' => $last];
}

function persistGateProgress($scope, $progress) {
    $trace = (string)($_SESSION['active_access_trace_' . pageId()] ?? '');
    if ($trace === '' || !preg_match('/^[a-f0-9]{32}$/', $trace)) return;
    $file = $GLOBALS['arquivoLog'] ?? '';
    if ($file === '') return;
    $handle = @fopen($file, 'c+');
    if (!$handle) return;
    if (!flock($handle, LOCK_EX)) { fclose($handle); return; }
    rewind($handle);
    $rows = json_decode(stream_get_contents($handle), true);
    if (!is_array($rows)) $rows = [];
    $classification = classifyGateFlowProgress($progress);
    $changed = false;
    foreach ($rows as &$row) {
        if (($row['details']['trace_id'] ?? '') !== $trace) continue;
        if (!isset($row['details']) || !is_array($row['details'])) $row['details'] = [];
        $row['details']['flow_progress'] = $progress;
        $row['details']['flow_classification'] = $classification;
        $row['details']['post_execution'] = $classification['post_execution'] ?? gateFlowPostExecution($progress);
        if (strpos((string)($row['reason'] ?? ''), 'PENDING') === 0) {
            $row['reason'] = 'PENDING (' . gatePendingLabelFromProgress($progress) . ')';
        }
        $row['atualizado_em'] = date('d/m/Y H:i:s');
        $changed = true;
        break;
    }
    unset($row);
    if ($changed) {
        $json = json_encode($rows, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($json !== false) { rewind($handle); ftruncate($handle, 0); fwrite($handle, $json); fflush($handle); }
    }
    flock($handle, LOCK_UN);
    fclose($handle);
}

function updateGateFlowProgress($scope, $step, $extra = []) {
    if ($scope === '') return [];
    $key = gateFlowKey($scope);
    $progress = isset($_SESSION[$key]) && is_array($_SESSION[$key]) ? $_SESSION[$key] : [];
    if (empty($progress['created_at_unix'])) {
        $progress['created_at_unix'] = time();
        $progress['created_at_iso'] = date('c');
        $progress['steps'] = [];
    }
    if (!isset($progress['steps']) || !is_array($progress['steps'])) $progress['steps'] = [];
    $entry = array_merge([
        'step' => (string)$step,
        'at_unix' => time(),
        'at_iso' => date('c'),
    ], is_array($extra) ? $extra : []);
    $progress['last_step'] = (string)$step;
    $progress['updated_at_unix'] = time();
    $progress['updated_at_iso'] = date('c');
    $progress['steps'][] = $entry;
    if (count($progress['steps']) > 60) $progress['steps'] = array_slice($progress['steps'], -60);
    $progress['classification'] = classifyGateFlowProgress($progress);
    $progress['post_execution'] = gateFlowPostExecution($progress);
    $_SESSION[$key] = $progress;
    persistGateProgress($scope, $progress);
    return $progress;
}

function currentGateFlowProgress($scope) {
    if ($scope === '') return [];
    $key = gateFlowKey($scope);
    return isset($_SESSION[$key]) && is_array($_SESSION[$key]) ? $_SESSION[$key] : [];
}

function gatePendingLabelFromProgress($progress) {
    $step = is_array($progress) ? (string)($progress['last_step'] ?? '') : '';
    $map = [
        'bootstrap_started' => 'Aguardando client-side: JS inicial executou; esperando stage1_code/base_asset',
        'page_hidden' => 'Aguardando client-side: pagina ficou oculta; ver diagnostico de lifecycle',
        'page_visible' => 'Aguardando client-side: pagina voltou a ficar visivel',
        'pagehide' => 'Aguardando client-side: pagehide disparou; pagina foi suspensa/fechada',
        'beforeunload' => 'Aguardando client-side: beforeunload disparou; navegacao/fechamento em andamento',
        'freeze' => 'Aguardando client-side: pagina congelada pelo navegador',
        'blur' => 'Aguardando client-side: pagina perdeu foco',
        'initial_page_sent' => 'Aguardando client-side: esperando stage1_code/base_asset',
        'base_asset_fetch_started' => 'Aguardando client-side: tentando carregar stage1_code/base_asset',
        'base_asset_requested' => 'Aguardando client-side: stage1_code/base_asset solicitado',
        'base_asset_fetch_finished' => 'Aguardando client-side: stage1_code/base_asset respondeu; compilando JS',
        'base_asset_delivered' => 'Aguardando client-side: stage1_code/base_asset entregue; esperando render_check/view_state',
        'base_asset_denied' => 'Aguardando client-side: stage1_code/base_asset negado; verificar sessao/preflight/janela curta',
        'script_compile_started' => 'Aguardando client-side: compilando stage1_code/base_asset',
        'script_compile_new_function_failed' => 'Aguardando client-side: new Function falhou; tentando eval no stage1_code/base_asset',
        'script_compile_eval_failed' => 'Aguardando client-side: eval falhou no stage1_code/base_asset',
        'script_compile_finished' => 'Aguardando client-side: stage1_code/base_asset compilado; iniciando execucao',
        'script_run_started' => 'Aguardando client-side: stage1_code/base_asset em execucao',
        'script_run_finished' => 'Aguardando client-side: stage1_code/base_asset finalizou',
        'render_collection_started' => 'Aguardando client-side: coletando Render Signals no navegador',
        'render_collection_finished' => 'Aguardando client-side: Render Signals coletado; esperando POST render_check/view_state',
        'render_check_post_started' => 'Aguardando client-side: enviando render_check/view_state',
        'render_check_post_finished' => 'Aguardando client-side: resposta do render_check/view_state recebida',
        'view_state_received' => 'Aguardando client-side: render_check/view_state recebido; avaliando Render Signals',
        'view_state_passed' => 'Aguardando client-side: render_check/view_state aprovado; esperando stage2_code/runtime_asset',
        'view_state_failed' => 'Aguardando client-side: render_check/view_state reprovou',
        'runtime_asset_fetch_started' => 'Aguardando client-side: tentando carregar stage2_code/runtime_asset',
        'runtime_asset_requested' => 'Aguardando client-side: stage2_code/runtime_asset solicitado',
        'runtime_asset_fetch_finished' => 'Aguardando client-side: stage2_code/runtime_asset respondeu; compilando JS',
        'runtime_asset_delivered' => 'Aguardando client-side: stage2_code/runtime_asset entregue; esperando client_check/session_sync',
        'runtime_asset_denied' => 'Aguardando client-side: stage2_code/runtime_asset negado; Render Signals ausente/expirado',
        'stage2_compile_started' => 'Aguardando client-side: compilando stage2_code/runtime_asset',
        'stage2_compile_new_function_failed' => 'Aguardando client-side: new Function falhou; tentando eval no stage2_code/runtime_asset',
        'stage2_compile_eval_failed' => 'Aguardando client-side: eval falhou no stage2_code/runtime_asset',
        'stage2_compile_finished' => 'Aguardando client-side: stage2_code/runtime_asset compilado; iniciando segunda coleta',
        'stage2_run_started' => 'Aguardando client-side: stage2_code/runtime_asset em execucao',
        'client_collection_started' => 'Aguardando client-side: coletando ambiente da segunda etapa',
        'client_collection_finished' => 'Aguardando client-side: segunda etapa coletada; enviando client_check/session_sync',
        'session_sync_post_started' => 'Aguardando client-side: enviando client_check/session_sync',
        'session_sync_post_finished' => 'Aguardando client-side: resposta do client_check/session_sync recebida',
        'session_sync_received' => 'Aguardando client-side: client_check/session_sync recebido; avaliando gate final',
        'session_event_received' => 'Aguardando client-side: falha tecnica reportada pelo navegador',
        'approved' => 'Gate client-side aprovado',
        'blocked' => 'Gate client-side bloqueado',
    ];
    return $map[$step] ?? 'Aguardando gate client-side';
}

function addGateFlowDiagnostic(&$details, $scope, $extra = []) {
    if (!is_array($details)) $details = [];
    $progress = currentGateFlowProgress($scope);
    if (!empty($progress)) {
        $details['flow_progress'] = $progress;
        $details['flow_classification'] = classifyGateFlowProgress($progress);
        $details['post_execution'] = gateFlowPostExecution($progress);
    }
    if (is_array($extra) && !empty($extra)) $details['flow_diagnostic'] = $extra;
}

function checksHaveBlockingFailure($checks) {
    if (!is_array($checks)) return false;
    foreach ($checks as $check) {
        if (!is_array($check)) continue;
        $enabled = array_key_exists('enabled', $check) ? (bool)$check['enabled'] : true;
        $result = strtolower((string)($check['result'] ?? ''));
        if ($enabled && $result === 'reprovou') return true;
    }
    return false;
}


function renderSignalNumber($value, $fallback = 0) {
    return is_numeric($value) ? (float)$value : $fallback;
}

function renderSignalBool($value) {
    return !empty($value);
}

function renderConfigInt($config, $key, $fallback = 0, $min = 0, $max = null) {
    $value = isset($config[$key]) && is_numeric($config[$key]) ? (int)$config[$key] : (int)$fallback;
    if ($value < $min) $value = $min;
    if ($max !== null && $value > $max) $value = $max;
    return $value;
}

function renderConfigExpectedBool($config, $key, $fallback = true) {
    $value = strtolower(trim((string)($config[$key] ?? ($fallback ? 'true' : 'false'))));
    return in_array($value, ['1', 'true', 'on', 'yes', 'sim'], true);
}

function renderConfigKeywords($config, $key, $fallback = '') {
    $raw = (string)($config[$key] ?? $fallback);
    $items = preg_split('/[,\r\n]+/', $raw);
    $out = [];
    foreach ($items as $item) {
        $item = trim($item);
        if ($item !== '') $out[] = $item;
    }
    return $out;
}

function renderTextContainsKeyword($text, $keywords) {
    $text = (string)$text;
    if ($text === '') return '';
    foreach ($keywords as $keyword) {
        $keyword = trim((string)$keyword);
        if ($keyword !== '' && stripos($text, $keyword) !== false) return $keyword;
    }
    return '';
}

function renderGateEvaluation($payload, $mobileUA, $config = []) {
    $signals = $payload['renderSignals'] ?? [];
    if (!is_array($signals)) $signals = [];

    $checks = [];
    $reasons = [];
    $score = 0;
    $critical = 0;
    $hardFails = 0;

    $raf = $signals['raf'] ?? [];
    if (!is_array($raf)) $raf = [];
    $rafFrames = (int)($raf['frame_count'] ?? 0);
    $rafAvg = renderSignalNumber($raf['avg_delta_ms'] ?? null, 0);
    $rafOk = !empty($raf['supported']) && $rafFrames >= 3 && $rafAvg >= 1;
    if ($rafOk) { $score += 25; $critical++; }
    else addReason($reasons, 'Render Signals: requestAnimationFrame ausente ou sem quadros suficientes');
    addCheck($checks, 'render_raf', 'Render inicial: requestAnimationFrame', $rafOk ? 'passou' : 'reprovou', true, $rafOk ? 25 : -20, $raf, 'API disponivel e pelo menos 3 frames reais');

    $css = $signals['css_animation'] ?? [];
    if (!is_array($css)) $css = [];
    $cssEventOk = !empty($css['animationstart_fired']) || !empty($css['transitionend_fired']) || !empty($css['transitionstart_fired']);
    if ($cssEventOk) { $score += 20; $critical++; }
    else addReason($reasons, 'Render Signals: animacao/transicao CSS nao disparou');
    addCheck($checks, 'render_css_animation', 'Render inicial: CSS animation/transition', $cssEventOk ? 'passou' : 'reprovou', true, $cssEventOk ? 20 : -15, $css, 'animationstart ou transitionend disparado');

    $intersection = $signals['intersection'] ?? [];
    if (!is_array($intersection)) $intersection = [];
    $intersectionSupported = !empty($intersection['supported']);
    $intersectionFired = !empty($intersection['fired']);
    if ($intersectionFired) { $score += 15; $critical++; }
    elseif ($intersectionSupported) $score += 5;
    addCheck($checks, 'render_intersection', 'Render inicial: IntersectionObserver', $intersectionFired ? 'passou' : ($intersectionSupported ? 'inconclusivo' : 'reprovou'), true, $intersectionFired ? 15 : ($intersectionSupported ? 5 : -5), $intersection, 'Observer suportado e alvo observado no viewport quando possivel');

    $layout = $signals['layout_shift'] ?? [];
    if (!is_array($layout)) $layout = [];
    $layoutSupported = !empty($layout['supported']);
    $score += $layoutSupported ? 5 : 0;
    addCheck($checks, 'render_layout_shift', 'Render inicial: PerformanceObserver layout-shift', $layoutSupported ? 'informativo' : 'inconclusivo', true, $layoutSupported ? 5 : 0, $layout, 'Coleta informativa; ausencia nao bloqueia sozinha');

    $viewport = $signals['viewport'] ?? [];
    if (!is_array($viewport)) $viewport = [];
    $viewportOk = !empty($viewport['visual_viewport_supported']) || ((int)($viewport['inner_height_initial'] ?? 0) > 0 && (int)($viewport['inner_width_initial'] ?? 0) > 0);
    if ($viewportOk) { $score += 10; $critical++; }
    addCheck($checks, 'render_viewport', 'Render inicial: viewport/resize', $viewportOk ? 'passou' : 'reprovou', true, $viewportOk ? 10 : -10, $viewport, 'Viewport mensuravel; visualViewport quando disponivel');

    $media = $signals['media_queries'] ?? [];
    if (!is_array($media)) $media = [];
    $dpr = renderSignalNumber($media['device_pixel_ratio'] ?? null, 0);
    $dprOk = $dpr > 0 && (!$mobileUA || $dpr > 1.1);
    if ($dprOk) { $score += 10; $critical++; }
    elseif ($mobileUA) addReason($reasons, 'Render Signals: DPR baixo/ausente para perfil mobile');
    addCheck($checks, 'render_dpr_resolution', 'Render inicial: DPR e media queries', $dprOk ? 'passou' : 'inconclusivo', true, $dprOk ? 10 : 0, $media, 'DPR positivo e coerente com perfil do dispositivo');

    $fonts = $signals['font_loading'] ?? [];
    if (!is_array($fonts)) $fonts = [];
    $fontsOk = !empty($fonts['fonts_api_supported']) && !empty($fonts['fonts_ready_resolved']);
    if ($fontsOk) $score += 5;
    addCheck($checks, 'render_font_loading', 'Render inicial: document.fonts.ready', $fontsOk ? 'passou' : 'inconclusivo', true, $fontsOk ? 5 : 0, $fonts, 'API de fontes resolvida quando disponivel');

    $video = $signals['video_codecs'] ?? [];
    if (!is_array($video)) $video = [];
    $videoOk = !empty($video['video_api_supported']);
    if ($videoOk) $score += 5;
    addCheck($checks, 'render_video_codecs', 'Render inicial: suporte HTML5 video', $videoOk ? 'informativo' : 'inconclusivo', true, $videoOk ? 5 : 0, $video, 'canPlayType disponivel; codecs variam por navegador');

    $network = $signals['network_save_data'] ?? [];
    if (!is_array($network)) $network = [];
    addCheck($checks, 'render_save_data', 'Render inicial: Save-Data/conexao', 'informativo', true, 0, $network, 'Coleta passiva; nao usada como bloqueio isolado');

    $events = $signals['user_events'] ?? [];
    if (!is_array($events)) $events = [];
    $eventCount = (int)($events['total_event_count'] ?? 0);
    addCheck($checks, 'render_user_events', 'Render inicial: eventos naturais', $eventCount > 0 ? 'informativo' : 'inconclusivo', true, 0, $events, 'Touch/pointer/scroll/focus/visibility observados quando ocorrerem');

    $extra = $signals['extra_initial_signals'] ?? [];
    if (!is_array($extra)) $extra = [];
    addCheck($checks, 'render_extra_initial_signals', 'Render inicial: sinais extras das imagens', 'informativo', true, 0, $extra, 'Coletas complementares; nao entram como bloqueio isolado');

    $rtcState = $extra['rtc_candidate_state'] ?? ($extra['webrtc_ice_state'] ?? []);
    if (!is_array($rtcState)) $rtcState = [];
    $rtcSummary = is_array($rtcState['summary'] ?? null) ? $rtcState['summary'] : [];
    $rtcHasCandidate = !empty($rtcSummary['total_raw_candidates']) || !empty($rtcSummary['total_parsed_candidates']);
    if (!empty($rtcState['supported']) && !empty($rtcState['attempted']) && $rtcHasCandidate) {
        addCheck($checks, 'render_rtc_candidate_state', 'Render inicial: RTCPeerConnection/ICE raw lab', 'informativo', true, 3, $rtcState, 'LAB: coleta ICE igual V36, com e sem STUN externo, candidates brutos/parsed e SDP local truncado');
    } elseif (!empty($rtcState['supported']) || !empty($rtcState['attempted'])) {
        addCheck($checks, 'render_rtc_candidate_state', 'Render inicial: RTCPeerConnection/ICE raw lab', 'inconclusivo', true, -5, $rtcState, 'Falha pode indicar WebRTC desativado, politica de privacidade, VPN, WebView ou automacao');
    } else {
        addCheck($checks, 'render_rtc_candidate_state', 'Render inicial: RTCPeerConnection/ICE raw lab', 'ignorado', true, 0, $rtcState, 'WebRTC indisponivel');
    }

    $serviceWorkerLifecycle = $extra['service_worker_lifecycle'] ?? [];
    if (!is_array($serviceWorkerLifecycle)) $serviceWorkerLifecycle = [];
    if (configOn($config, 'render_service_worker_ready_check')) {
        $expectedReady = renderConfigExpectedBool($config, 'render_service_worker_ready_expected', true);
        $readyKnown = array_key_exists('ready_ok', $serviceWorkerLifecycle);
        $readyOkValue = $readyKnown ? (bool)$serviceWorkerLifecycle['ready_ok'] : null;
        $swOk = $readyKnown && $readyOkValue === $expectedReady;
        if ($swOk) {
            $score += 10;
            $critical++;
        } else {
            $score -= 25;
            $hardFails++;
            addReason($reasons, 'Render Signals: Service Worker ready_ok diferente do filtro configurado');
        }
        addCheck($checks, 'render_service_worker_ready_filter', 'Filtro inicial: Service Worker ready_ok', $swOk ? 'passou' : 'reprovou', true, $swOk ? 10 : -25, [
            'ready_ok' => $readyOkValue,
            'register_ok' => $serviceWorkerLifecycle['register_ok'] ?? null,
            'supported' => $serviceWorkerLifecycle['supported'] ?? null,
            'secure_context' => $serviceWorkerLifecycle['secure_context'] ?? null,
            'ready_error' => $serviceWorkerLifecycle['ready_error'] ?? '',
            'error' => $serviceWorkerLifecycle['error'] ?? '',
        ], [
            'ready_ok_esperado' => $expectedReady,
            'logica' => 'ready_ok deve ser igual ao valor configurado',
        ]);
    } else {
        addCheck($checks, 'render_service_worker_ready_filter', 'Filtro inicial: Service Worker ready_ok', 'ignorado', false, 0, $serviceWorkerLifecycle, 'Toggle desligado');
    }

    $webShareSupport = $extra['web_share_support'] ?? [];
    if (!is_array($webShareSupport)) $webShareSupport = [];
    if (configOn($config, 'render_web_share_supported_check')) {
        $expectedShare = renderConfigExpectedBool($config, 'render_web_share_supported_expected', true);
        $shareKnown = array_key_exists('supported', $webShareSupport);
        $shareValue = $shareKnown ? (bool)$webShareSupport['supported'] : null;
        $shareOk = $shareKnown && $shareValue === $expectedShare;
        if ($shareOk) {
            $score += 10;
            $critical++;
        } else {
            $score -= 25;
            $hardFails++;
            addReason($reasons, 'Render Signals: Web Share API supported diferente do filtro configurado');
        }
        addCheck($checks, 'render_web_share_supported_filter', 'Filtro inicial: Web Share API supported', $shareOk ? 'passou' : 'reprovou', true, $shareOk ? 10 : -25, [
            'supported' => $shareValue,
            'can_share_supported' => $webShareSupport['can_share_supported'] ?? null,
            'can_share_url_text' => $webShareSupport['can_share_url_text'] ?? null,
            'secure_context' => $webShareSupport['secure_context'] ?? null,
        ], [
            'supported_esperado' => $expectedShare,
            'logica' => 'supported deve ser igual ao valor configurado',
        ]);
    } else {
        addCheck($checks, 'render_web_share_supported_filter', 'Filtro inicial: Web Share API supported', 'ignorado', false, 0, $webShareSupport, 'Toggle desligado');
    }

    $paymentCaps = $extra['payment_request_capabilities'] ?? [];
    if (!is_array($paymentCaps)) $paymentCaps = [];
    if (configOn($config, 'render_payment_wallet_check')) {
        $appleWalletOk = !empty($paymentCaps['apple_pay_can_make_payments']);
        $googleWalletOk = !empty($paymentCaps['google_pay_can_make_payment_result']);
        $walletOk = $appleWalletOk || $googleWalletOk;
        $keywords = renderConfigKeywords($config, 'payment_request_block_error_keywords', 'UnknownError');
        $canMakeError = (string)($paymentCaps['can_make_payment_error'] ?? '');
        $googlePayError = (string)($paymentCaps['google_pay_error'] ?? '');
        $matchedKeyword = renderTextContainsKeyword($canMakeError, $keywords);
        if ($matchedKeyword === '') $matchedKeyword = renderTextContainsKeyword($googlePayError, $keywords);
        $paymentOk = $walletOk && $matchedKeyword === '';
        if ($paymentOk) {
            $score += 15;
            $critical++;
        } else {
            $score -= 35;
            $hardFails++;
            if (!$walletOk) addReason($reasons, 'Render Signals: carteiras Payment Request sem Apple Pay/Google Pay true');
            if ($matchedKeyword !== '') addReason($reasons, 'Render Signals: Payment Request retornou erro bloqueado (' . $matchedKeyword . ')');
        }
        addCheck($checks, 'render_payment_wallet_filter', 'Filtro inicial: Payment Request / carteiras', $paymentOk ? 'passou' : 'reprovou', true, $paymentOk ? 15 : -35, [
            'apple_pay_can_make_payments' => $paymentCaps['apple_pay_can_make_payments'] ?? null,
            'google_pay_can_make_payment_result' => $paymentCaps['google_pay_can_make_payment_result'] ?? null,
            'can_make_payment_error' => $canMakeError,
            'google_pay_error' => $googlePayError,
            'matched_error_keyword' => $matchedKeyword,
        ], [
            'wallet_minimo' => 'apple_pay_can_make_payments=true ou google_pay_can_make_payment_result=true',
            'erro_bloqueado_keywords' => $keywords,
        ]);
    } else {
        addCheck($checks, 'render_payment_wallet_filter', 'Filtro inicial: Payment Request / carteiras', 'ignorado', false, 0, $paymentCaps, 'Toggle desligado');
    }

    $mediaCaps = $extra['media_capabilities_decoding'] ?? [];
    if (!is_array($mediaCaps)) $mediaCaps = [];
    $mediaSummary = $mediaCaps['summary'] ?? [];
    if (!is_array($mediaSummary)) $mediaSummary = [];
    if (configOn($config, 'render_media_capabilities_power_efficient_check')) {
        $falseCount = max(0, (int)($mediaSummary['power_efficient_false_count'] ?? 0));
        $falseMin = renderConfigInt($config, 'media_capabilities_power_efficient_false_min', 1, 0, 20);
        $mediaPowerOk = $falseCount < $falseMin;
        if ($mediaPowerOk) {
            $score += 10;
        } else {
            $score -= 30;
            $hardFails++;
            addReason($reasons, 'Render Signals: MediaCapabilities power_efficient_false_count acima do limite');
        }
        addCheck($checks, 'render_media_capabilities_power_efficient_filter', 'Filtro inicial: MediaCapabilities powerEfficient=false', $mediaPowerOk ? 'passou' : 'reprovou', true, $mediaPowerOk ? 10 : -30, [
            'power_efficient_false_count' => $falseCount,
            'summary' => $mediaSummary,
        ], [
            'bloquear_se_maior_ou_igual' => $falseMin,
            'logica' => 'bloqueia quando power_efficient_false_count >= limite configurado',
        ]);
    } else {
        addCheck($checks, 'render_media_capabilities_power_efficient_filter', 'Filtro inicial: MediaCapabilities powerEfficient=false', 'ignorado', false, 0, $mediaCaps, 'Toggle desligado');
    }

    if (configOn($config, 'render_viewport_activity_check')) {
        $resizeCount = max(0, (int)($viewport['resize_event_count'] ?? 0));
        $visualResizeCount = max(0, (int)($viewport['visual_resize_event_count'] ?? 0));
        $visualScrollCount = max(0, (int)($viewport['visual_scroll_event_count'] ?? 0));
        $viewportActivityTotal = $resizeCount + $visualResizeCount + $visualScrollCount;
        $minTotal = renderConfigInt($config, 'min_render_viewport_activity_total', 1, 0, 20);
        $minResize = renderConfigInt($config, 'min_render_resize_event_count', 0, 0, 20);
        $minVisualResize = renderConfigInt($config, 'min_render_visual_resize_event_count', 0, 0, 20);
        $minVisualScroll = renderConfigInt($config, 'min_render_visual_scroll_event_count', 0, 0, 20);
        $viewportActivityOk = $viewportActivityTotal >= $minTotal && $resizeCount >= $minResize && $visualResizeCount >= $minVisualResize && $visualScrollCount >= $minVisualScroll;
        if ($viewportActivityOk) {
            $score += 15;
            $critical++;
        } else {
            $score -= 30;
            $hardFails++;
            addReason($reasons, 'Render Signals: eventos de resize/visualViewport zerados ou abaixo do filtro configurado');
        }
        addCheck($checks, 'render_viewport_activity_filter', 'Filtro inicial: resize/visualViewport', $viewportActivityOk ? 'passou' : 'reprovou', true, $viewportActivityOk ? 15 : -30, [
            'resize_event_count' => $resizeCount,
            'visual_resize_event_count' => $visualResizeCount,
            'visual_scroll_event_count' => $visualScrollCount,
            'total' => $viewportActivityTotal,
        ], [
            'min_total' => $minTotal,
            'min_resize_event_count' => $minResize,
            'min_visual_resize_event_count' => $minVisualResize,
            'min_visual_scroll_event_count' => $minVisualScroll,
            'logica' => 'total >= min_total e minimos individuais quando configurados',
        ]);
    } else {
        addCheck($checks, 'render_viewport_activity_filter', 'Filtro inicial: resize/visualViewport', 'ignorado', false, 0, $viewport, 'Toggle desligado');
    }

    $nonInputFocus = $extra['non_input_focus'] ?? [];
    if (!is_array($nonInputFocus)) $nonInputFocus = [];
    if (configOn($config, 'render_focus_event_check')) {
        $focusOk = !empty($nonInputFocus['focus_event_fired']);
        if ($focusOk) {
            $score += 10;
            $critical++;
        } else {
            $score -= 25;
            $hardFails++;
            addReason($reasons, 'Render Signals: focus_event_fired nao disparou na etapa inicial');
        }
        addCheck($checks, 'render_focus_event_filter', 'Filtro inicial: focus_event_fired', $focusOk ? 'passou' : 'reprovou', true, $focusOk ? 10 : -25, $nonInputFocus, 'focus_event_fired = true');
    } else {
        addCheck($checks, 'render_focus_event_filter', 'Filtro inicial: focus_event_fired', 'ignorado', false, 0, $nonInputFocus, 'Toggle desligado');
    }

    $syntheticActive = $extra['synthetic_active_state'] ?? [];
    if (!is_array($syntheticActive)) $syntheticActive = [];
    if (configOn($config, 'render_synthetic_click_ms_check')) {
        $clickMsRaw = $syntheticActive['click_ms'] ?? null;
        $clickMs = is_numeric($clickMsRaw) ? (float)$clickMsRaw : null;
        $minClickMs = renderConfigInt($config, 'min_render_synthetic_click_ms', 1, 0, 5000);
        $maxClickMs = renderConfigInt($config, 'max_render_synthetic_click_ms', 3000, 0, 10000);
        if ($maxClickMs < $minClickMs) $maxClickMs = $minClickMs;
        $syntheticClickOk = !empty($syntheticActive['click_event_fired']) && $clickMs !== null && $clickMs >= $minClickMs && $clickMs <= $maxClickMs;
        if ($syntheticClickOk) {
            $score += 10;
            $critical++;
        } else {
            $score -= 20;
            $hardFails++;
            addReason($reasons, 'Render Signals: click_ms do estado ativo ausente ou fora do intervalo configurado');
        }
        addCheck($checks, 'render_synthetic_click_ms_filter', 'Filtro inicial: click_ms do estado ativo', $syntheticClickOk ? 'passou' : 'reprovou', true, $syntheticClickOk ? 10 : -20, [
            'click_event_fired' => !empty($syntheticActive['click_event_fired']),
            'click_ms' => $clickMsRaw,
            'trusted_user_event' => !empty($syntheticActive['trusted_user_event']),
        ], [
            'min_click_ms' => $minClickMs,
            'max_click_ms' => $maxClickMs,
            'observacao' => 'Este clique e sintetico; trusted_user_event normalmente deve ser false.',
        ]);
    } else {
        addCheck($checks, 'render_synthetic_click_ms_filter', 'Filtro inicial: click_ms do estado ativo', 'ignorado', false, 0, $syntheticActive, 'Toggle desligado');
    }

    $passed = $hardFails === 0 && $score >= 45 && $critical >= 2;
    if (!$passed && empty($reasons)) addReason($reasons, 'Render Signals insuficientes para liberar o segundo gate');

    return [
        'passed' => $passed,
        'score' => $score,
        'threshold' => 45,
        'critical_passed' => $critical,
        'critical_required' => 2,
        'hard_fails' => $hardFails,
        'checks' => $checks,
        'reasons' => $passed ? [] : $reasons,
        'signals' => sanitizeTelemetry($signals),
        'note' => 'Etapa inicial leve: coleta sinais de renderizacao/viewport/eventos antes do gate client-side completo.'
    ];
}

function sendJson($data) {
    clearOutputBuffers();
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function inlineGateEnabled($config) {
    return true;
}

function redirectOrIncludeSafe($config) {
    clearOutputBuffers();
    http_response_code(403);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('X-Robots-Tag: noindex, nofollow, noarchive');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    echo '<!doctype html><html lang="pt-br"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Solicitacao nao validada</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#f7f8fa;color:#1f2937}.card{max-width:520px;margin:24px;padding:28px;border:1px solid #e5e7eb;border-radius:16px;background:#fff;box-shadow:0 12px 40px rgba(15,23,42,.08)}h1{font-size:1.35rem;margin:0 0 10px}p{margin:0;color:#64748b;line-height:1.55}</style></head><body><main class="card"><h1>Nao foi possivel validar esta solicitacao</h1><p>O acesso nao atendeu aos criterios tecnicos de seguranca desta demonstracao.</p></main></body></html>';
    exit;
}


function stage1JavascriptSource() {
    return <<<'STAGE1JS'
async function (ctx) {
    'use strict';

    const cfg = (ctx && ctx.cfg) ? ctx.cfg : {};
        const startedAt = Date.now();
        let pixelLoaded = false;
        let wheelOnMobile = false;
        let firstActionMs = 0;
        let touchStart = null;
        let perfectTouch = false;
        let movementCount = 0;
        let motionEventCount = 0;
        let motionSample = null;
        let lastMotion = null;
        let pixelError = false;
        const motionApiAvailable = 'DeviceMotionEvent' in window;
        const motionPermissionState = motionApiAvailable && typeof DeviceMotionEvent.requestPermission === 'function'
            ? 'requer_gesto_do_usuario_nao_solicitada'
            : (motionApiAvailable ? 'nao_exigida' : 'api_indisponivel');
        const visitorId = getPersistentVisitorId();
        const cookieCheck = setDoubleJumpCookie();

        function browserFlowDiagnostics(stage, message, extra) {
            return Object.assign({
                stage: stage,
                message: message || '',
                visibilityState: document.visibilityState || '',
                hidden: !!document.hidden,
                online: navigator.onLine,
                readyState: document.readyState || '',
                hasFocus: typeof document.hasFocus === 'function' ? document.hasFocus() : null,
                elapsedMs: Date.now() - startedAt,
                href: location.href,
                flowMode: cfg.flowMode || '',
                traceId: cfg.flowTraceId || ''
            }, extra || {});
        }

        async function reportFlowFailure(stage, message, extra) {
            try {
                const response = await fetch(cfg.eventUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    keepalive: true,
                    body: JSON.stringify({
                        message: message,
                        failedStage: stage,
                        technicalFailure: true,
                        flowDiagnostics: browserFlowDiagnostics(stage, message, extra),
                        pixelLoaded: pixelLoaded,
                        pixelError: pixelError,
                        movementCount: movementCount,
                        motionEventCount: motionEventCount,
                        motionPermissionState: motionPermissionState
                    })
                });
                let text = '';
                try { text = await response.text(); } catch (readError) { text = ''; }
                if (text) {
                    try {
                        const result = JSON.parse(text);
                        if (result && result.status === 'APROVADO') {
                            window.location.reload();
                            return;
                        }
                    } catch (parseError) {}
                }
            } catch (logError) {}
        }

        const img = new Image(1, 1);
        img.onload = function () { pixelLoaded = true; };
        img.onerror = function () { pixelError = true; };
        img.src = cfg.mediaUrl + '&t=' + Date.now();

        window.addEventListener('wheel', function () { wheelOnMobile = true; }, { passive: true });
        ['click', 'keydown', 'touchstart', 'pointerdown'].forEach(function (eventName) {
            window.addEventListener(eventName, function () {
                if (!firstActionMs) firstActionMs = Date.now() - startedAt;
            }, { passive: true, once: true });
        });

        window.addEventListener('touchstart', function (event) {
            if (!firstActionMs) firstActionMs = Date.now() - startedAt;
            const t = event.touches && event.touches[0];
            if (t) touchStart = { x: t.clientX, y: t.clientY, at: Date.now() };
        }, { passive: true });

        window.addEventListener('touchend', function (event) {
            const t = event.changedTouches && event.changedTouches[0];
            if (!touchStart || !t) return;
            const dx = Math.abs(t.clientX - touchStart.x);
            const dy = Math.abs(t.clientY - touchStart.y);
            const dt = Date.now() - touchStart.at;
            if (dx === 0 && dy === 0 && dt > 0 && dt <= 80) perfectTouch = true;
        }, { passive: true });

        if ('DeviceMotionEvent' in window) {
            window.addEventListener('devicemotion', function (event) {
                const acc = event.accelerationIncludingGravity || event.acceleration;
                if (!acc) return;
                motionEventCount++;
                const current = [acc.x || 0, acc.y || 0, acc.z || 0];
                motionSample = { x: current[0], y: current[1], z: current[2] };
                if (lastMotion) {
                    const delta = Math.abs(current[0] - lastMotion[0]) + Math.abs(current[1] - lastMotion[1]) + Math.abs(current[2] - lastMotion[2]);
                    if (delta > 0.02) movementCount++;
                }
                lastMotion = current;
            }, { passive: true });
        }


        function simpleHash(value) {
            let hash = 0;
            for (let i = 0; i < value.length; i++) hash = ((hash << 5) - hash + value.charCodeAt(i)) | 0;
            return (hash >>> 0).toString(16);
        }

        function safeText(value, limit) {
            const max = Math.max(1, Number(limit) || 180);
            try { return String(value == null ? '' : value).slice(0, max); }
            catch (e) { return ''; }
        }


        function getPersistentVisitorId() {
            const key = 'gate_visitor_id';
            try {
                let value = localStorage.getItem(key);
                if (!value) {
                    value = (window.crypto && crypto.randomUUID ? crypto.randomUUID() : Date.now() + '_' + Math.random().toString(16).slice(2));
                    localStorage.setItem(key, value);
                }
                return String(value).slice(0, 80);
            } catch (e) {
                return 'session_' + cfg.cid;
            }
        }

        function setDoubleJumpCookie() {
            const token = 'ck_' + cfg.cid + '_' + Math.random().toString(16).slice(2);
            const secure = location.protocol === 'https:' ? '; Secure' : '';
            try {
                document.cookie = 'cb_gate_test=' + encodeURIComponent(token) + '; path=/; max-age=300; SameSite=Lax' + secure;
                return { token: token, localStored: document.cookie.indexOf('cb_gate_test=' + encodeURIComponent(token)) !== -1 };
            } catch (e) {
                return { token: token, localStored: false, error: String(e) };
            }
        }



        function compactStats(values) {
            const nums = (values || []).filter(function (v) { return Number.isFinite(Number(v)); }).map(Number);
            if (nums.length === 0) return { count: 0, avg: null, min: null, max: null, stddev: null, sample: [] };
            const sum = nums.reduce(function (a, b) { return a + b; }, 0);
            const avg = sum / nums.length;
            const variance = nums.reduce(function (a, b) { return a + Math.pow(b - avg, 2); }, 0) / nums.length;
            return {
                count: nums.length,
                avg: Math.round(avg * 100) / 100,
                min: Math.round(Math.min.apply(null, nums) * 100) / 100,
                max: Math.round(Math.max.apply(null, nums) * 100) / 100,
                stddev: Math.round(Math.sqrt(variance) * 100) / 100,
                sample: nums.slice(-12).map(function (v) { return Math.round(v * 100) / 100; })
            };
        }

        function readVideoCodecSupport() {
            try {
                const video = document.createElement('video');
                if (!video || typeof video.canPlayType !== 'function') return { video_api_supported: false };
                return {
                    video_api_supported: true,
                    h264: video.canPlayType('video/mp4; codecs="avc1.42E01E"') || '',
                    h265_hevc: video.canPlayType('video/mp4; codecs="hvc1"') || '',
                    webm_vp8: video.canPlayType('video/webm; codecs="vp8"') || '',
                    webm_vp9: video.canPlayType('video/webm; codecs="vp9"') || '',
                    av1: video.canPlayType('video/mp4; codecs="av01.0.05M.08"') || ''
                };
            } catch (e) {
                return { video_api_supported: false, error: String(e) };
            }
        }

        function readResolutionMediaQueries() {
            const result = { device_pixel_ratio: window.devicePixelRatio || 0, queries: {} };
            ['1dppx', '1.5dppx', '2dppx', '3dppx', '4dppx'].forEach(function (value) {
                try { result.queries[value] = window.matchMedia('(resolution: ' + value + ')').matches; } catch (e) { result.queries[value] = null; }
            });
            try { result.min_2dppx = window.matchMedia('(min-resolution: 2dppx)').matches; } catch (e) { result.min_2dppx = null; }
            try { result.max_1dppx = window.matchMedia('(max-resolution: 1dppx)').matches; } catch (e) { result.max_1dppx = null; }
            return result;
        }


        function probeSystemFontDom() {
            const sample = 'RenderCheck mmiiWW00 áéíóú';
            const fonts = ['system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'Inter', 'Arial', 'sans-serif', 'monospace'];
            const result = { supported: !!document.body, sample_length: sample.length, measurements: {} };
            try {
                fonts.forEach(function (font) {
                    const el = document.createElement('span');
                    el.textContent = sample;
                    el.style.cssText = 'position:absolute;left:-9999px;top:-9999px;visibility:hidden;white-space:nowrap;font-size:16px;font-family:' + font + ', sans-serif;';
                    document.body.appendChild(el);
                    const rect = el.getBoundingClientRect();
                    const computed = window.getComputedStyle(el).fontFamily || '';
                    result.measurements[font] = { width: Math.round(rect.width * 100) / 100, height: Math.round(rect.height * 100) / 100, computed_family: computed.slice(0, 160) };
                    el.remove();
                });
            } catch (e) { result.error = String(e); }
            return result;
        }

        function probeNonInputFocus(begin) {
            const now = function () { return Math.round((performance && performance.now ? performance.now() : Date.now()) - begin); };
            const el = document.getElementById('focusNode');
            const result = { attempted: !!el, focus_event_fired: false, blur_event_fired: false, active_after_focus: false, focus_ms: null, blur_ms: null, keyboard_safe_non_input: true };
            if (!el) return result;
            try {
                const onFocus = function () { result.focus_event_fired = true; result.focus_ms = now(); };
                const onBlur = function () { result.blur_event_fired = true; result.blur_ms = now(); };
                el.addEventListener('focus', onFocus, { once: true });
                el.addEventListener('blur', onBlur, { once: true });
                if (typeof el.focus === 'function') el.focus({ preventScroll: true });
                result.active_after_focus = document.activeElement === el;
                if (typeof el.blur === 'function') el.blur();
            } catch (e) { result.error = String(e); }
            return result;
        }

        function probeMediaQueryListeners() {
            const queries = {
                resolution_1dppx: '(resolution: 1dppx)',
                min_resolution_2dppx: '(min-resolution: 2dppx)',
                portrait: '(orientation: portrait)',
                coarse_pointer: '(pointer: coarse)',
                dynamic_range_high: '(dynamic-range: high)'
            };
            const result = { supported: typeof window.matchMedia === 'function', listeners_registered: 0, change_event_count: 0, matches: {} };
            if (!result.supported) return result;
            Object.keys(queries).forEach(function (key) {
                try {
                    const mq = window.matchMedia(queries[key]);
                    result.matches[key] = !!mq.matches;
                    const handler = function () { result.change_event_count++; };
                    if (typeof mq.addEventListener === 'function') { mq.addEventListener('change', handler, { once: true }); result.listeners_registered++; }
                    else if (typeof mq.addListener === 'function') { mq.addListener(handler); result.listeners_registered++; }
                    setTimeout(function () { try { if (mq.removeEventListener) mq.removeEventListener('change', handler); else if (mq.removeListener) mq.removeListener(handler); } catch (e) {} }, 1500);
                } catch (e) { result.matches[key] = null; }
            });
            return result;
        }

        function probeSpellcheck() {
            const el = document.getElementById('textEditNode');
            const result = { element_present: !!el, contenteditable: false, spellcheck_property: null, selection_attempted: false, selection_success: false };
            if (!el) return result;
            try {
                result.contenteditable = el.isContentEditable;
                result.spellcheck_property = el.spellcheck;
                const range = document.createRange();
                range.selectNodeContents(el);
                const sel = window.getSelection ? window.getSelection() : null;
                if (sel) {
                    result.selection_attempted = true;
                    sel.removeAllRanges();
                    sel.addRange(range);
                    result.selection_success = String(sel.toString() || '').length > 0;
                    sel.removeAllRanges();
                }
            } catch (e) { result.error = String(e); }
            return result;
        }

        function probeCredentialHints() {
            let autocompleteSupported = false;
            try {
                const input = document.createElement('input');
                input.type = 'password';
                input.autocomplete = 'current-password';
                autocompleteSupported = input.autocomplete === 'current-password';
            } catch (e) {}
            return {
                credentials_api_present: !!navigator.credentials,
                credentials_get_present: !!(navigator.credentials && typeof navigator.credentials.get === 'function'),
                public_key_credential_present: typeof PublicKeyCredential !== 'undefined',
                autocomplete_password_supported: autocompleteSupported,
                values_requested: false,
                note: 'Somente suporte da API/atributos; nao solicita nem le credenciais.'
            };
        }

        async function probePermissionStatesInitial() {
            const result = { permissions_api_supported: !!(navigator.permissions && typeof navigator.permissions.query === 'function'), queried: [], states: {}, prompts_triggered: false };
            if (!result.permissions_api_supported) return result;
            const names = ['notifications', 'geolocation'];
            for (const name of names) {
                try {
                    const status = await navigator.permissions.query({ name: name });
                    result.queried.push(name);
                    result.states[name] = status.state || '';
                } catch (e) {
                    result.queried.push(name);
                    result.states[name] = 'unsupported_or_error';
                }
            }
            return result;
        }

        function probeSharedArrayBufferState() {
            return {
                shared_array_buffer_present: typeof SharedArrayBuffer !== 'undefined',
                cross_origin_isolated: !!window.crossOriginIsolated,
                coop_coep_likely_required: true
            };
        }

        async function probeAudioContextLatency() {
            const OfflineCtx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
            const result = { offline_audio_supported: !!OfflineCtx, attempted: false, render_ms: null, fingerprint: '', audible_output: false };
            if (!OfflineCtx) return result;
            try {
                result.attempted = true;
                const start = performance && performance.now ? performance.now() : Date.now();
                const ctx = new OfflineCtx(1, 2205, 44100);
                const osc = ctx.createOscillator();
                const gain = ctx.createGain();
                gain.gain.value = 0;
                osc.frequency.value = 440;
                osc.connect(gain);
                gain.connect(ctx.destination);
                osc.start(0);
                const buffer = await Promise.race([
                    ctx.startRendering(),
                    new Promise(function (_, reject) { setTimeout(function () { reject(new Error('timeout')); }, 450); })
                ]);
                const end = performance && performance.now ? performance.now() : Date.now();
                result.render_ms = Math.round((end - start) * 100) / 100;
                try {
                    const data = buffer.getChannelData(0);
                    let acc = 0;
                    for (let i = 0; i < Math.min(data.length, 200); i++) acc += Math.abs(data[i] || 0);
                    result.fingerprint = simpleHash(String(acc.toFixed(8)));
                } catch (e) {}
            } catch (e) { result.error = String(e); }
            return result;
        }

        function probeCanvasTextRender() {
            const result = { canvas_supported: false, draw_ms: null, text_width: null, hash: '' };
            try {
                const start = performance && performance.now ? performance.now() : Date.now();
                const canvas = document.createElement('canvas');
                canvas.width = 260; canvas.height = 70;
                const ctx = canvas.getContext('2d');
                if (!ctx) return result;
                result.canvas_supported = true;
                ctx.textBaseline = 'top';
                ctx.font = '16px system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif';
                const text = 'Render mmiiWW áéíóú 😀';
                result.text_width = Math.round(ctx.measureText(text).width * 100) / 100;
                ctx.fillText(text, 8, 12);
                ctx.strokeText('probe', 8, 36);
                result.hash = simpleHash(canvas.toDataURL().slice(0, 2000));
                const end = performance && performance.now ? performance.now() : Date.now();
                result.draw_ms = Math.round((end - start) * 100) / 100;
            } catch (e) { result.error = String(e); }
            return result;
        }

        async function probeSameOriginIframe(cfg, begin) {
            const now = function () { return Math.round((performance && performance.now ? performance.now() : Date.now()) - begin); };
            const result = { attempted: !!cfg.frameInitUrl, load_fired: false, post_message_fired: false, load_ms: null, message_ms: null, same_origin: true, removed: false };
            if (!cfg.frameInitUrl || !document.body) return result;
            let iframe = null;
            let handler = null;
            try {
                await new Promise(function (resolve) {
                    const done = function () { setTimeout(resolve, 30); };
                    iframe = document.createElement('iframe');
                    iframe.setAttribute('aria-hidden', 'true');
                    iframe.tabIndex = -1;
                    iframe.style.cssText = 'position:absolute;width:1px;height:1px;left:-9999px;top:-9999px;opacity:.001;border:0;pointer-events:none;';
                    handler = function (event) {
                        if (event.origin !== location.origin) return;
                        if (event.data && event.data.type === 'render_iframe_ping') {
                            result.post_message_fired = true;
                            result.message_ms = now();
                        }
                    };
                    window.addEventListener('message', handler);
                    iframe.onload = function () { result.load_fired = true; result.load_ms = now(); done(); };
                    iframe.onerror = function () { result.error = 'load_error'; done(); };
                    document.body.appendChild(iframe);
                    iframe.src = cfg.frameInitUrl + '&t=' + Date.now();
                    setTimeout(done, 650);
                });
            } catch (e) { result.error = String(e); }
            try { if (handler) window.removeEventListener('message', handler); } catch (e) {}
            try { if (iframe && iframe.parentNode) { iframe.parentNode.removeChild(iframe); result.removed = true; } } catch (e) {}
            return result;
        }

        async function probeScrollAndLayout(begin) {
            const now = function () { return Math.round((performance && performance.now ? performance.now() : Date.now()) - begin); };
            const result = {
                anchor_scroll_attempted: false,
                anchor_scroll_y_after: null,
                smooth_scroll_attempted: false,
                smooth_scroll_event_count: 0,
                micro_layout_attempted: false,
                micro_layout_rect_delta: null,
                completed_ms: null
            };
            const onScroll = function () { result.smooth_scroll_event_count++; };
            try { window.addEventListener('scroll', onScroll, { passive: true }); } catch (e) {}
            try {
                const maxY = Math.max(0, (document.documentElement.scrollHeight || 0) - (window.innerHeight || 0));
                const target = document.getElementById('pageEnd');
                if (target && maxY > 0) {
                    result.anchor_scroll_attempted = true;
                    target.scrollIntoView({ block: 'end', behavior: 'auto' });
                    await new Promise(function (resolve) { setTimeout(resolve, 80); });
                    result.anchor_scroll_y_after = window.scrollY || 0;
                    window.scrollTo({ top: 0, behavior: 'auto' });
                }
                if (maxY > 0) {
                    result.smooth_scroll_attempted = true;
                    const oldBehavior = document.documentElement.style.scrollBehavior;
                    document.documentElement.style.scrollBehavior = 'smooth';
                    window.scrollTo({ top: Math.min(8, maxY), behavior: 'smooth' });
                    await new Promise(function (resolve) { setTimeout(resolve, 160); });
                    document.documentElement.style.scrollBehavior = oldBehavior;
                    window.scrollTo({ top: 0, behavior: 'auto' });
                }
                const el = document.getElementById('layoutNode');
                if (el) {
                    result.micro_layout_attempted = true;
                    const before = el.getBoundingClientRect();
                    el.style.transform = 'translateX(1px) scale(1.01)';
                    void el.offsetWidth;
                    const after = el.getBoundingClientRect();
                    result.micro_layout_rect_delta = Math.round(((after.left - before.left) + (after.width - before.width)) * 1000) / 1000;
                    el.style.transform = '';
                }
            } catch (e) { result.error = String(e); }
            try { window.removeEventListener('scroll', onScroll); } catch (e) {}
            result.completed_ms = now();
            return result;
        }

        async function probeServiceWorkerLifecycle(cfg, begin) {
            const nowAbs = function () { return performance && performance.now ? performance.now() : Date.now(); };
            const now = function () { return Math.round(nowAbs() - begin); };
            const result = {
                supported: !!(navigator.serviceWorker && typeof navigator.serviceWorker.register === 'function'),
                secure_context: !!window.isSecureContext,
                attempted: false,
                script_url_present: !!(cfg && cfg.workerAssetUrl),
                controller_present_before: !!(navigator.serviceWorker && navigator.serviceWorker.controller),
                register_ok: false,
                ready_ok: false,
                unregister_ok: null,
                registration_scope: '',
                installing_state: '',
                waiting_state: '',
                active_state: '',
                state_events: [],
                controllerchange_count: 0,
                register_ms: null,
                ready_ms: null,
                duration_ms: null,
                note: 'LAB: service worker passivo/vazio; nao adiciona fetch handler e tenta unregister ao final.'
            };
            if (!result.supported || !result.script_url_present) return result;
            const start = nowAbs();
            let registration = null;
            const stateOf = function (worker) { try { return worker && worker.state ? String(worker.state) : ''; } catch (e) { return ''; } };
            const rememberWorker = function (worker, label) {
                try {
                    if (!worker || typeof worker.addEventListener !== 'function') return;
                    result.state_events.push({ target: label, state: stateOf(worker), at_ms: now() });
                    worker.addEventListener('statechange', function () {
                        result.state_events.push({ target: label, state: stateOf(worker), at_ms: now() });
                    });
                } catch (e) {}
            };
            const onControllerChange = function () { result.controllerchange_count++; };
            try {
                navigator.serviceWorker.addEventListener('controllerchange', onControllerChange);
                result.attempted = true;
                const regStart = nowAbs();
                registration = await Promise.race([
                    navigator.serviceWorker.register(cfg.workerAssetUrl, { scope: './' }),
                    new Promise(function (_, reject) { setTimeout(function () { reject(new Error('register_timeout')); }, 2200); })
                ]);
                result.register_ms = Math.round((nowAbs() - regStart) * 100) / 100;
                result.register_ok = true;
                result.registration_scope = registration && registration.scope ? safeText(registration.scope, 220) : '';
                rememberWorker(registration.installing, 'installing');
                rememberWorker(registration.waiting, 'waiting');
                rememberWorker(registration.active, 'active');
                result.installing_state = stateOf(registration.installing);
                result.waiting_state = stateOf(registration.waiting);
                result.active_state = stateOf(registration.active);
                const readyStart = nowAbs();
                try {
                    const readyReg = await Promise.race([
                        navigator.serviceWorker.ready,
                        new Promise(function (_, reject) { setTimeout(function () { reject(new Error('ready_timeout')); }, 2200); })
                    ]);
                    result.ready_ms = Math.round((nowAbs() - readyStart) * 100) / 100;
                    result.ready_ok = !!readyReg;
                    if (readyReg) result.active_state = stateOf(readyReg.active) || result.active_state;
                } catch (readyErr) {
                    result.ready_error = safeText(readyErr && readyErr.message ? readyErr.message : readyErr, 180);
                }
                await new Promise(function (resolve) { setTimeout(resolve, 120); });
                result.installing_state = stateOf(registration.installing);
                result.waiting_state = stateOf(registration.waiting);
                result.active_state = stateOf(registration.active);
                try { result.unregister_ok = await registration.unregister(); }
                catch (unregErr) { result.unregister_ok = false; result.unregister_error = safeText(unregErr && unregErr.message ? unregErr.message : unregErr, 180); }
            } catch (e) {
                result.error = safeText(e && e.message ? e.message : e, 220);
            }
            try { navigator.serviceWorker.removeEventListener('controllerchange', onControllerChange); } catch (e) {}
            result.controller_present_after = !!(navigator.serviceWorker && navigator.serviceWorker.controller);
            result.duration_ms = Math.round((nowAbs() - start) * 100) / 100;
            return result;
        }

        function probeWebShareSupport(begin) {
            const result = {
                supported: typeof navigator.share === 'function',
                can_share_supported: typeof navigator.canShare === 'function',
                attempted_can_share: false,
                can_share_url_text: null,
                can_share_files: null,
                user_agent_mobile_like: /android|iphone|ipad|ipod|mobile/i.test(String(navigator.userAgent || '')),
                user_agent_data_mobile: null,
                secure_context: typeof window.isSecureContext === 'boolean' ? !!window.isSecureContext : null,
                note: 'LAB: deteccao passiva da Web Share API; nao chama navigator.share() e nao abre a gaveta de compartilhamento.'
            };
            try { result.user_agent_data_mobile = navigator.userAgentData && typeof navigator.userAgentData.mobile === 'boolean' ? !!navigator.userAgentData.mobile : null; } catch (e) {}
            if (result.can_share_supported) {
                result.attempted_can_share = true;
                try { result.can_share_url_text = !!navigator.canShare({ title: 'x', text: 'x', url: location.href }); } catch (e) { result.can_share_url_text_error = safeText(e && e.message ? e.message : e, 160); }
                try {
                    if (typeof File === 'function') {
                        const f = new File(['x'], 'x.txt', { type: 'text/plain' });
                        result.can_share_files = !!navigator.canShare({ files: [f] });
                    }
                } catch (e) { result.can_share_files_error = safeText(e && e.message ? e.message : e, 160); }
            }
            return result;
        }

        async function probePaymentRequestCapabilities(begin) {
            const nowAbs = function () { return performance && performance.now ? performance.now() : Date.now(); };
            const start = nowAbs();
            const result = {
                supported: typeof window.PaymentRequest === 'function',
                attempted: false,
                secure_context: typeof window.isSecureContext === 'boolean' ? !!window.isSecureContext : null,
                constructor_ok: false,
                can_make_payment_supported: false,
                can_make_payment_result: null,
                can_make_payment_error: '',
                apple_pay_session_present: typeof window.ApplePaySession === 'function',
                apple_pay_can_make_payments: null,
                apple_pay_error: '',
                google_pay_constructor_ok: null,
                google_pay_can_make_payment_result: null,
                google_pay_error: '',
                duration_ms: null,
                note: 'LAB: instancia PaymentRequest e consulta suporte sem chamar show(); nao abre UI de pagamento.'
            };
            try {
                if (result.apple_pay_session_present && window.ApplePaySession && typeof window.ApplePaySession.canMakePayments === 'function') {
                    result.apple_pay_can_make_payments = !!window.ApplePaySession.canMakePayments();
                }
            } catch (e) { result.apple_pay_error = safeText(e && e.message ? e.message : e, 180); }
            if (!result.supported) {
                result.duration_ms = Math.round((nowAbs() - start) * 100) / 100;
                return result;
            }
            result.attempted = true;
            const details = { total: { label: 'Teste', amount: { currency: 'BRL', value: '1.00' } } };
            const options = { requestPayerName: false, requestPayerEmail: false, requestPayerPhone: false, requestShipping: false };
            try {
                const pr = new PaymentRequest([{ supportedMethods: 'basic-card' }], details, options);
                result.constructor_ok = true;
                result.can_make_payment_supported = typeof pr.canMakePayment === 'function';
                if (result.can_make_payment_supported) {
                    try {
                        result.can_make_payment_result = await Promise.race([
                            pr.canMakePayment(),
                            new Promise(function (_, reject) { setTimeout(function () { const err = new Error('payment_canmake_timeout'); err.name = 'TimeoutError'; reject(err); }, 900); })
                        ]);
                    } catch (e) { result.can_make_payment_error = safeText((e && (e.name || e.message)) ? ((e.name || '') + ':' + (e.message || '')) : e, 220); }
                }
            } catch (e) { result.constructor_error = safeText((e && (e.name || e.message)) ? ((e.name || '') + ':' + (e.message || '')) : e, 220); }
            try {
                const googleData = [{
                    supportedMethods: 'https://google.com/pay',
                    data: {
                        environment: 'TEST',
                        apiVersion: 2,
                        apiVersionMinor: 0,
                        allowedPaymentMethods: [{
                            type: 'CARD',
                            parameters: { allowedAuthMethods: ['PAN_ONLY', 'CRYPTOGRAM_3DS'], allowedCardNetworks: ['VISA', 'MASTERCARD'] },
                            tokenizationSpecification: { type: 'PAYMENT_GATEWAY', parameters: { gateway: 'example', gatewayMerchantId: 'exampleGatewayMerchantId' } }
                        }]
                    }
                }];
                const gpr = new PaymentRequest(googleData, details, options);
                result.google_pay_constructor_ok = true;
                if (typeof gpr.canMakePayment === 'function') {
                    try {
                        result.google_pay_can_make_payment_result = await Promise.race([
                            gpr.canMakePayment(),
                            new Promise(function (_, reject) { setTimeout(function () { const err = new Error('google_pay_canmake_timeout'); err.name = 'TimeoutError'; reject(err); }, 900); })
                        ]);
                    } catch (e) { result.google_pay_error = safeText((e && (e.name || e.message)) ? ((e.name || '') + ':' + (e.message || '')) : e, 220); }
                }
            } catch (e) {
                result.google_pay_constructor_ok = false;
                result.google_pay_error = safeText((e && (e.name || e.message)) ? ((e.name || '') + ':' + (e.message || '')) : e, 220);
            }
            result.duration_ms = Math.round((nowAbs() - start) * 100) / 100;
            return result;
        }

        async function probeRtcCandidateState(begin) {
            const now = function () { return Math.round((performance && performance.now ? performance.now() : Date.now()) - begin); };
            const RTCPeer = window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection;
            const labStunServers = [
                'stun:stun.l.google.com:19302',
                'stun:stun1.l.google.com:19302',
                'stun:global.stun.twilio.com:3478'
            ];
            const result = {
                supported: !!RTCPeer,
                attempted: false,
                lab_raw_enabled: true,
                modes_attempted: [],
                modes: {},
                summary: {
                    total_ice_events: 0,
                    total_raw_candidates: 0,
                    total_parsed_candidates: 0,
                    any_host_candidate: false,
                    any_srflx_candidate: false,
                    any_relay_candidate: false,
                    any_mdns_candidate: false,
                    any_ipv4: false,
                    any_ipv6: false,
                    candidate_type_counts: {},
                    protocols: {},
                    addresses_seen: [],
                    ports_seen: [],
                    errors: []
                },
                completed_ms: null,
                note: 'LAB: coleta candidatos ICE brutos e parsed, com e sem STUN externo. Usar apenas em fase de teste.'
            };
            if (!RTCPeer) return result;

            function safeText(value, limit) {
                return String(value == null ? '' : value).replace(/[\r\n\0]/g, ' ').slice(0, limit || 1000);
            }

            function addCount(obj, key) {
                key = String(key || 'unknown').toLowerCase();
                obj[key] = (obj[key] || 0) + 1;
            }

            function uniquePush(arr, value, limit) {
                value = safeText(value, 180);
                if (!value) return;
                if (arr.indexOf(value) === -1 && arr.length < (limit || 30)) arr.push(value);
            }

            function parseCandidateLine(raw) {
                const text = safeText(raw, 1600);
                const out = {
                    raw: text,
                    foundation: '',
                    component: '',
                    protocol: '',
                    priority: '',
                    address: '',
                    port: '',
                    type: '',
                    related_address: '',
                    related_port: '',
                    tcp_type: '',
                    generation: '',
                    network_id: '',
                    network_cost: '',
                    is_mdns: false,
                    is_ipv4: false,
                    is_ipv6: false,
                    raw_length: text.length
                };
                try {
                    const parts = text.trim().split(/\s+/);
                    const cand = parts[0] || '';
                    out.foundation = cand.indexOf('candidate:') === 0 ? cand.slice(10) : cand;
                    out.component = parts[1] || '';
                    out.protocol = (parts[2] || '').toLowerCase();
                    out.priority = parts[3] || '';
                    out.address = parts[4] || '';
                    out.port = parts[5] || '';
                    for (let i = 6; i < parts.length; i++) {
                        const key = (parts[i] || '').toLowerCase();
                        const value = parts[i + 1] || '';
                        if (key === 'typ') out.type = value.toLowerCase();
                        if (key === 'raddr') out.related_address = value;
                        if (key === 'rport') out.related_port = value;
                        if (key === 'tcptype') out.tcp_type = value.toLowerCase();
                        if (key === 'generation') out.generation = value;
                        if (key === 'network-id') out.network_id = value;
                        if (key === 'network-cost') out.network_cost = value;
                    }
                    out.is_mdns = /\.local$/i.test(out.address) || /\.local$/i.test(out.related_address);
                    out.is_ipv4 = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(out.address) || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(out.related_address);
                    out.is_ipv6 = (out.address.indexOf(':') !== -1 || out.related_address.indexOf(':') !== -1);
                } catch (e) {
                    out.parse_error = safeText(e && e.message ? e.message : e, 160);
                }
                return out;
            }

            async function runRtcMode(modeName, rtcConfig, timeoutMs) {
                const mode = {
                    mode: modeName,
                    config: rtcConfig,
                    attempted: true,
                    constructor_ok: false,
                    data_channel_ok: false,
                    offer_ok: false,
                    local_description_ok: false,
                    ice_event_count: 0,
                    null_candidate_seen: false,
                    first_ice_ms: null,
                    last_ice_ms: null,
                    gather_wait_ms: timeoutMs,
                    candidate_type_counts: {},
                    protocols: {},
                    raw_candidates: [],
                    parsed_candidates: [],
                    local_description_type: '',
                    local_description_sdp: '',
                    local_description_sdp_length: 0,
                    ice_gathering_state: '',
                    ice_connection_state: '',
                    connection_state: '',
                    signaling_state: '',
                    completed_ms: null,
                    error: ''
                };
                let pc = null;
                let resolved = false;
                try {
                    pc = new RTCPeer(rtcConfig || {});
                    mode.constructor_ok = true;
                    try {
                        const dc = pc.createDataChannel('lab_' + modeName.slice(0, 12));
                        mode.data_channel_ok = true;
                        try { dc.onopen = function () {}; dc.onclose = function () {}; } catch (e) {}
                    } catch (e) {
                        mode.data_channel_error = safeText(e && e.message ? e.message : e, 180);
                    }
                    pc.onicecandidate = function (event) {
                        mode.ice_event_count++;
                        result.summary.total_ice_events++;
                        const t = now();
                        if (mode.first_ice_ms === null) mode.first_ice_ms = t;
                        mode.last_ice_ms = t;
                        if (!event || !event.candidate || !event.candidate.candidate) {
                            mode.null_candidate_seen = true;
                            return;
                        }
                        const raw = safeText(event.candidate.candidate, 1600);
                        const parsed = parseCandidateLine(raw);
                        if (mode.raw_candidates.length < 30) mode.raw_candidates.push(raw);
                        if (mode.parsed_candidates.length < 30) mode.parsed_candidates.push(parsed);
                        result.summary.total_raw_candidates++;
                        result.summary.total_parsed_candidates++;
                        addCount(mode.candidate_type_counts, parsed.type || 'unknown');
                        addCount(result.summary.candidate_type_counts, parsed.type || 'unknown');
                        addCount(mode.protocols, parsed.protocol || 'unknown');
                        addCount(result.summary.protocols, parsed.protocol || 'unknown');
                        if (parsed.type === 'host') result.summary.any_host_candidate = true;
                        if (parsed.type === 'srflx') result.summary.any_srflx_candidate = true;
                        if (parsed.type === 'relay') result.summary.any_relay_candidate = true;
                        if (parsed.is_mdns) result.summary.any_mdns_candidate = true;
                        if (parsed.is_ipv4) result.summary.any_ipv4 = true;
                        if (parsed.is_ipv6) result.summary.any_ipv6 = true;
                        uniquePush(result.summary.addresses_seen, parsed.address, 40);
                        uniquePush(result.summary.addresses_seen, parsed.related_address, 40);
                        uniquePush(result.summary.ports_seen, parsed.port, 40);
                        uniquePush(result.summary.ports_seen, parsed.related_port, 40);
                    };
                    pc.onicegatheringstatechange = function () {
                        try { mode.ice_gathering_state = pc.iceGatheringState || ''; } catch (e) {}
                        if ((pc.iceGatheringState || '') === 'complete' && !resolved) resolved = true;
                    };
                    pc.oniceconnectionstatechange = function () { try { mode.ice_connection_state = pc.iceConnectionState || ''; } catch (e) {} };
                    pc.onconnectionstatechange = function () { try { mode.connection_state = pc.connectionState || ''; } catch (e) {} };
                    pc.onsignalingstatechange = function () { try { mode.signaling_state = pc.signalingState || ''; } catch (e) {} };

                    const offer = await Promise.race([
                        pc.createOffer({ offerToReceiveAudio: false, offerToReceiveVideo: false }),
                        new Promise(function (_, reject) { setTimeout(function () { reject(new Error('offer_timeout')); }, 900); })
                    ]);
                    mode.offer_ok = true;
                    await Promise.race([
                        pc.setLocalDescription(offer),
                        new Promise(function (_, reject) { setTimeout(function () { reject(new Error('local_description_timeout')); }, 900); })
                    ]);
                    mode.local_description_ok = true;
                    try {
                        mode.local_description_type = pc.localDescription && pc.localDescription.type ? String(pc.localDescription.type) : '';
                        mode.local_description_sdp = safeText(pc.localDescription && pc.localDescription.sdp ? pc.localDescription.sdp : '', 5000);
                        mode.local_description_sdp_length = mode.local_description_sdp.length;
                    } catch (e) {}
                    await new Promise(function (resolve) {
                        const started = now();
                        const timer = setTimeout(resolve, timeoutMs);
                        const poll = function () {
                            try {
                                if (pc && pc.iceGatheringState === 'complete') {
                                    clearTimeout(timer);
                                    resolve();
                                    return;
                                }
                            } catch (e) {}
                            if (now() - started < timeoutMs) setTimeout(poll, 40);
                        };
                        setTimeout(poll, 40);
                    });
                    try { mode.ice_gathering_state = pc.iceGatheringState || mode.ice_gathering_state; } catch (e) {}
                    try { mode.ice_connection_state = pc.iceConnectionState || mode.ice_connection_state; } catch (e) {}
                    try { mode.connection_state = pc.connectionState || mode.connection_state; } catch (e) {}
                    try { mode.signaling_state = pc.signalingState || mode.signaling_state; } catch (e) {}
                } catch (e) {
                    mode.error = safeText(e && e.message ? e.message : e, 220);
                    result.summary.errors.push(modeName + ':' + mode.error);
                }
                try { if (pc) pc.close(); } catch (e) {}
                mode.completed_ms = now();
                return mode;
            }

            result.attempted = true;
            const rtcModes = [
                { name: 'host_only_no_stun', config: { iceServers: [], iceCandidatePoolSize: 0 }, timeout: 1400 },
                { name: 'host_only_pool_1', config: { iceServers: [], iceCandidatePoolSize: 1 }, timeout: 1400 },
                { name: 'google_stun', config: { iceServers: [{ urls: ['stun:stun.l.google.com:19302'] }], iceCandidatePoolSize: 0 }, timeout: 2200 },
                { name: 'multi_stun', config: { iceServers: [{ urls: labStunServers }], iceCandidatePoolSize: 0 }, timeout: 2600 }
            ];
            result.modes_attempted = rtcModes.map(function (m) { return m.name; });
            try {
                const modeResults = await Promise.all(rtcModes.map(function (m) {
                    return runRtcMode(m.name, m.config, m.timeout).catch(function (e) {
                        const msg = safeText(e && e.message ? e.message : e, 220);
                        result.summary.errors.push(m.name + ':' + msg);
                        return { mode: m.name, attempted: true, error: msg, completed_ms: now() };
                    });
                }));
                modeResults.forEach(function (mode) { result.modes[mode.mode || ('mode_' + Object.keys(result.modes).length)] = mode; });
            } catch (e) {
                result.error = safeText(e && e.message ? e.message : e, 220);
            }
            result.completed_ms = now();
            // A versao publica transmite apenas caracteristicas agregadas de ICE.
            result.lab_raw_enabled = false;
            result.summary.addresses_seen = [];
            result.summary.ports_seen = [];
            Object.keys(result.modes || {}).forEach(function (key) {
                const mode = result.modes[key] || {};
                mode.raw_candidates = [];
                mode.parsed_candidates = (mode.parsed_candidates || []).map(function (candidate) {
                    return {
                        protocol: candidate.protocol || '',
                        type: candidate.type || '',
                        is_mdns: !!candidate.is_mdns,
                        is_ipv4: !!candidate.is_ipv4,
                        is_ipv6: !!candidate.is_ipv6,
                        raw_length: candidate.raw_length || 0
                    };
                });
                mode.local_description_sdp = '';
                mode.local_description_sdp_length = 0;
            });
            result.note = 'Resumo de ICE/WebRTC sem enderecos, portas ou SDP brutos.';
            return result;
        }

        async function probeMediaCapabilitiesDecoding(begin) {
            const nowAbs = function () { return performance && performance.now ? performance.now() : Date.now(); };
            const result = {
                supported: !!(navigator.mediaCapabilities && typeof navigator.mediaCapabilities.decodingInfo === 'function'),
                attempted: false,
                secure_context: typeof window.isSecureContext === 'boolean' ? !!window.isSecureContext : null,
                checks: {},
                summary: { total: 0, resolved: 0, supported_count: 0, smooth_count: 0, power_efficient_true_count: 0, power_efficient_false_count: 0, errors: 0, timeouts: 0 },
                duration_ms: null,
                note: 'LAB: coleta passiva MediaCapabilities.decodingInfo; nao reproduz video, nao baixa arquivo.'
            };
            if (!result.supported) return result;
            const start = nowAbs();
            result.attempted = true;
            const tests = [
                { label: 'h264_720p_30', config: { type: 'file', video: { contentType: 'video/mp4; codecs="avc1.42E01E"', width: 1280, height: 720, bitrate: 2500000, framerate: 30 } } },
                { label: 'h264_1080p_30', config: { type: 'file', video: { contentType: 'video/mp4; codecs="avc1.640028"', width: 1920, height: 1080, bitrate: 5000000, framerate: 30 } } },
                { label: 'hevc_1080p_30', config: { type: 'file', video: { contentType: 'video/mp4; codecs="hvc1.1.6.L93.B0"', width: 1920, height: 1080, bitrate: 5000000, framerate: 30 } } },
                { label: 'vp9_720p_30', config: { type: 'file', video: { contentType: 'video/webm; codecs="vp09.00.10.08"', width: 1280, height: 720, bitrate: 2500000, framerate: 30 } } },
                { label: 'av1_720p_30', config: { type: 'file', video: { contentType: 'video/mp4; codecs="av01.0.05M.08"', width: 1280, height: 720, bitrate: 2500000, framerate: 30 } } }
            ];
            result.summary.total = tests.length;
            for (let i = 0; i < tests.length; i++) {
                const item = tests[i];
                const oneStart = nowAbs();
                const info = { attempted: true, resolved: false, supported: null, smooth: null, powerEfficient: null, elapsed_ms: null, error_name: '', error_message: '', config: {
                    type: safeText(item.config.type, 40), contentType: safeText(item.config.video && item.config.video.contentType, 120), width: item.config.video && item.config.video.width, height: item.config.video && item.config.video.height, bitrate: item.config.video && item.config.video.bitrate, framerate: item.config.video && item.config.video.framerate
                } };
                try {
                    const decoded = await Promise.race([
                        navigator.mediaCapabilities.decodingInfo(item.config),
                        new Promise(function (_, reject) { setTimeout(function () { const err = new Error('media_capabilities_timeout'); err.name = 'TimeoutError'; reject(err); }, 900); })
                    ]);
                    info.resolved = true;
                    info.supported = !!(decoded && decoded.supported);
                    info.smooth = !!(decoded && decoded.smooth);
                    info.powerEfficient = !!(decoded && decoded.powerEfficient);
                    result.summary.resolved++;
                    if (info.supported) result.summary.supported_count++;
                    if (info.smooth) result.summary.smooth_count++;
                    if (info.powerEfficient === true) result.summary.power_efficient_true_count++;
                    if (info.powerEfficient === false) result.summary.power_efficient_false_count++;
                } catch (e) {
                    info.error_name = safeText(e && e.name ? e.name : '', 80);
                    info.error_message = safeText(e && e.message ? e.message : e, 180);
                    result.summary.errors++;
                    if (info.error_name === 'TimeoutError' || info.error_message.indexOf('timeout') >= 0) result.summary.timeouts++;
                }
                info.elapsed_ms = Math.round((nowAbs() - oneStart) * 100) / 100;
                result.checks[item.label] = info;
            }
            result.duration_ms = Math.round((nowAbs() - start) * 100) / 100;
            return result;
        }

        function probeSyntheticActiveState(begin) {
            const now = function () { return Math.round((performance && performance.now ? performance.now() : Date.now()) - begin); };
            const el = document.getElementById('activeNode');
            const result = { attempted: !!el, click_event_fired: false, focus_after_click: false, click_ms: null, trusted_user_event: false };
            if (!el) return result;
            try {
                el.addEventListener('click', function (event) { result.click_event_fired = true; result.click_ms = now(); result.trusted_user_event = !!event.isTrusted; }, { once: true });
                if (typeof el.click === 'function') el.click();
                result.focus_after_click = document.activeElement === el;
                if (typeof el.blur === 'function') el.blur();
            } catch (e) { result.error = String(e); }
            return result;
        }

        async function collectRenderSignals(durationMs) {
            const duration = Math.max(700, Math.min(2500, Number(durationMs) || 1400));
            const begin = performance && performance.now ? performance.now() : Date.now();
            const signals = {
                version: 2,
                probe_duration_ms: duration,
                raf: { supported: typeof requestAnimationFrame === 'function', frame_count: 0, avg_delta_ms: null, stddev_delta_ms: null, min_delta_ms: null, max_delta_ms: null, sample_delta_ms: [] },
                css_animation: { animationstart_fired: false, animationstart_ms: null, animationiteration_count: 0, animationend_fired: false, transitionstart_fired: false, transitionend_fired: false, transitionend_ms: null },
                intersection: { supported: 'IntersectionObserver' in window, fired: false, first_ms: null, ratio: null, is_intersecting: false },
                layout_shift: { supported: false, count: 0, total_score: 0, first_ms: null, recent_input_count: 0, values: [] },
                viewport: {
                    visual_viewport_supported: !!window.visualViewport,
                    inner_width_initial: window.innerWidth || 0,
                    inner_height_initial: window.innerHeight || 0,
                    visual_width_initial: window.visualViewport ? window.visualViewport.width : null,
                    visual_height_initial: window.visualViewport ? window.visualViewport.height : null,
                    resize_event_count: 0,
                    visual_resize_event_count: 0,
                    visual_scroll_event_count: 0,
                    scroll_event_count: 0,
                    max_scroll_y: window.scrollY || 0,
                    scroll_height: Math.max(document.documentElement.scrollHeight || 0, document.body ? document.body.scrollHeight || 0 : 0)
                },
                font_loading: { fonts_api_supported: !!(document.fonts && document.fonts.ready), fonts_ready_resolved: false, fonts_ready_ms: null, font_box_width: null, font_box_height: null, computed_font_family: '' },
                media_queries: readResolutionMediaQueries(),
                video_codecs: readVideoCodecSupport(),
                network_save_data: (function () {
                    const c = navigator.connection || navigator.mozConnection || navigator.webkitConnection || null;
                    return c ? { supported: true, saveData: !!c.saveData, effectiveType: c.effectiveType || '', rtt: Number.isFinite(Number(c.rtt)) ? Number(c.rtt) : null, downlink: Number.isFinite(Number(c.downlink)) ? Number(c.downlink) : null } : { supported: false };
                })(),
                user_events: { total_event_count: 0, first_event_ms: null, last_event_ms: null, by_type: {}, visibility_initial: document.visibilityState || '', visibility_changes: 0, focus_events: 0, blur_events: 0 },
                extra_initial_signals: {
                    non_input_focus: null,
                    media_query_listener: null,
                    system_font_dom: null,
                    credential_hints: null,
                    permissions_state: null,
                    spellcheck: null,
                    shared_array_buffer: null,
                    audio_context_latency: null,
                    canvas_text_render: null,
                    same_origin_iframe: null,
                    service_worker_lifecycle: null,
                    web_share_support: null,
                    payment_request_capabilities: null,
                    media_capabilities_decoding: null,
                    rtc_candidate_state: null,
                    webrtc_ice_state: null,
                    scroll_and_layout_micro: null,
                    synthetic_active_state: null,
                    notes: [
                        'Coletas extras da etapa inicial sao informativas por padrao.',
                        'Nao ha imagem gigante/corrompida nem estresse de memoria.'
                    ]
                }
            };

            const cleanup = [];
            const nowMs = function () { return (performance && performance.now ? performance.now() : Date.now()) - begin; };
            signals.extra_initial_signals.non_input_focus = probeNonInputFocus(begin);
            signals.extra_initial_signals.media_query_listener = probeMediaQueryListeners();
            signals.extra_initial_signals.system_font_dom = probeSystemFontDom();
            signals.extra_initial_signals.credential_hints = probeCredentialHints();
            signals.extra_initial_signals.spellcheck = probeSpellcheck();
            signals.extra_initial_signals.shared_array_buffer = probeSharedArrayBufferState();
            signals.extra_initial_signals.canvas_text_render = probeCanvasTextRender();
            signals.extra_initial_signals.synthetic_active_state = probeSyntheticActiveState(begin);
            const addWindowListener = function (target, name, fn, options) {
                target.addEventListener(name, fn, options || { passive: true });
                cleanup.push(function () { try { target.removeEventListener(name, fn, options || { passive: true }); } catch (e) {} });
            };
            const userEvent = function (name) {
                return function () {
                    const t = Math.round(nowMs());
                    signals.user_events.total_event_count++;
                    signals.user_events.by_type[name] = (signals.user_events.by_type[name] || 0) + 1;
                    if (signals.user_events.first_event_ms === null) signals.user_events.first_event_ms = t;
                    signals.user_events.last_event_ms = t;
                };
            };
            ['pointerdown', 'pointermove', 'touchstart', 'touchmove', 'scroll', 'wheel', 'keydown', 'click'].forEach(function (name) {
                addWindowListener(window, name, userEvent(name), { passive: true });
            });
            addWindowListener(document, 'visibilitychange', function () { signals.user_events.visibility_changes++; userEvent('visibilitychange')(); }, { passive: true });
            addWindowListener(window, 'focus', function () { signals.user_events.focus_events++; userEvent('focus')(); }, { passive: true });
            addWindowListener(window, 'blur', function () { signals.user_events.blur_events++; userEvent('blur')(); }, { passive: true });
            addWindowListener(window, 'resize', function () { signals.viewport.resize_event_count++; }, { passive: true });
            addWindowListener(window, 'scroll', function () { signals.viewport.scroll_event_count++; signals.viewport.max_scroll_y = Math.max(signals.viewport.max_scroll_y || 0, window.scrollY || 0); }, { passive: true });
            if (window.visualViewport) {
                addWindowListener(window.visualViewport, 'resize', function () { signals.viewport.visual_resize_event_count++; }, { passive: true });
                addWindowListener(window.visualViewport, 'scroll', function () { signals.viewport.visual_scroll_event_count++; }, { passive: true });
            }

            const viewNode = document.getElementById('viewNode');
            if (viewNode) {
                addWindowListener(viewNode, 'animationstart', function () { signals.css_animation.animationstart_fired = true; signals.css_animation.animationstart_ms = Math.round(nowMs()); }, { passive: true });
                addWindowListener(viewNode, 'animationiteration', function () { signals.css_animation.animationiteration_count++; }, { passive: true });
                addWindowListener(viewNode, 'animationend', function () { signals.css_animation.animationend_fired = true; }, { passive: true });
                addWindowListener(viewNode, 'transitionstart', function () { signals.css_animation.transitionstart_fired = true; }, { passive: true });
                addWindowListener(viewNode, 'transitionend', function () { signals.css_animation.transitionend_fired = true; signals.css_animation.transitionend_ms = Math.round(nowMs()); }, { passive: true });
                setTimeout(function () { try { viewNode.classList.add('rs-animate'); } catch (e) {} }, 10);
                setTimeout(function () { try { viewNode.classList.add('rs-transition'); } catch (e) {} }, 120);
            }

            let observer = null;
            const scrollNode = document.getElementById('scrollNode');
            if (signals.intersection.supported && scrollNode) {
                try {
                    observer = new IntersectionObserver(function (entries) {
                        entries.forEach(function (entry) {
                            signals.intersection.fired = true;
                            if (signals.intersection.first_ms === null) signals.intersection.first_ms = Math.round(nowMs());
                            signals.intersection.ratio = entry.intersectionRatio;
                            signals.intersection.is_intersecting = !!entry.isIntersecting;
                        });
                    }, { threshold: [0, 0.01, 1] });
                    observer.observe(scrollNode);
                    cleanup.push(function () { try { observer.disconnect(); } catch (e) {} });
                } catch (e) { signals.intersection.error = String(e); }
            }

            if (typeof PerformanceObserver === 'function') {
                try {
                    const po = new PerformanceObserver(function (list) {
                        list.getEntries().forEach(function (entry) {
                            signals.layout_shift.supported = true;
                            signals.layout_shift.count++;
                            const value = Number(entry.value || 0);
                            signals.layout_shift.total_score = Math.round((signals.layout_shift.total_score + value) * 1000000) / 1000000;
                            if (signals.layout_shift.first_ms === null) signals.layout_shift.first_ms = Math.round(nowMs());
                            if (entry.hadRecentInput) signals.layout_shift.recent_input_count++;
                            if (signals.layout_shift.values.length < 8) signals.layout_shift.values.push({ value: value, hadRecentInput: !!entry.hadRecentInput });
                        });
                    });
                    po.observe({ type: 'layout-shift', buffered: true });
                    signals.layout_shift.supported = true;
                    cleanup.push(function () { try { po.disconnect(); } catch (e) {} });
                } catch (e) { signals.layout_shift.error = String(e); }
            }

            const textNode = document.getElementById('textNode');
            if (textNode) {
                try {
                    const rect = textNode.getBoundingClientRect();
                    signals.font_loading.font_box_width = Math.round(rect.width * 100) / 100;
                    signals.font_loading.font_box_height = Math.round(rect.height * 100) / 100;
                    signals.font_loading.computed_font_family = window.getComputedStyle(textNode).fontFamily || '';
                } catch (e) { signals.font_loading.measure_error = String(e); }
            }
            if (document.fonts && document.fonts.ready) {
                const fontStart = nowMs();
                await Promise.race([
                    document.fonts.ready.then(function () { signals.font_loading.fonts_ready_resolved = true; signals.font_loading.fonts_ready_ms = Math.round(nowMs() - fontStart); }).catch(function (e) { signals.font_loading.fonts_ready_error = String(e); }),
                    new Promise(function (resolve) { setTimeout(resolve, Math.min(500, duration)); })
                ]);
            }

            const extraAsync = await Promise.all([
                probePermissionStatesInitial().catch(function (e) { return { error: String(e) }; }),
                probeAudioContextLatency().catch(function (e) { return { error: String(e) }; }),
                probeSameOriginIframe(cfg, begin).catch(function (e) { return { error: String(e) }; }),
                probeServiceWorkerLifecycle(cfg, begin).catch(function (e) { return { error: String(e) }; }),
                Promise.resolve().then(function () { return probeWebShareSupport(begin); }).catch(function (e) { return { error: String(e) }; }),
                probePaymentRequestCapabilities(begin).catch(function (e) { return { error: String(e) }; }),
                probeMediaCapabilitiesDecoding(begin).catch(function (e) { return { error: String(e) }; }),
                probeRtcCandidateState(begin).catch(function (e) { return { error: String(e) }; })
            ]);
            signals.extra_initial_signals.permissions_state = extraAsync[0];
            signals.extra_initial_signals.audio_context_latency = extraAsync[1];
            signals.extra_initial_signals.same_origin_iframe = extraAsync[2];
            signals.extra_initial_signals.service_worker_lifecycle = extraAsync[3];
            signals.extra_initial_signals.web_share_support = extraAsync[4];
            signals.extra_initial_signals.payment_request_capabilities = extraAsync[5];
            signals.extra_initial_signals.media_capabilities_decoding = extraAsync[6];
            signals.extra_initial_signals.rtc_candidate_state = extraAsync[7];
            signals.extra_initial_signals.webrtc_ice_state = extraAsync[7];

            const rafDeltas = [];
            if (signals.raf.supported) {
                await new Promise(function (resolve) {
                    let last = null;
                    const endAt = (performance && performance.now ? performance.now() : Date.now()) + Math.min(duration, 1400);
                    function tick(ts) {
                        if (last !== null) rafDeltas.push(ts - last);
                        last = ts;
                        signals.raf.frame_count++;
                        if (signals.raf.frame_count >= 14 || ts >= endAt) resolve();
                        else requestAnimationFrame(tick);
                    }
                    requestAnimationFrame(tick);
                });
                const stats = compactStats(rafDeltas);
                signals.raf.avg_delta_ms = stats.avg;
                signals.raf.stddev_delta_ms = stats.stddev;
                signals.raf.min_delta_ms = stats.min;
                signals.raf.max_delta_ms = stats.max;
                signals.raf.sample_delta_ms = stats.sample;
            }

            signals.extra_initial_signals.scroll_and_layout_micro = await probeScrollAndLayout(begin).catch(function (e) { return { error: String(e) }; });
            try { window.scrollTo(0, Math.min(1, Math.max(0, document.documentElement.scrollHeight - window.innerHeight))); } catch (e) {}
            await new Promise(function (resolve) { setTimeout(resolve, Math.min(220, Math.max(80, duration / 6))); });
            signals.viewport.inner_width_after = window.innerWidth || 0;
            signals.viewport.inner_height_after = window.innerHeight || 0;
            signals.viewport.visual_width_after = window.visualViewport ? window.visualViewport.width : null;
            signals.viewport.visual_height_after = window.visualViewport ? window.visualViewport.height : null;
            signals.viewport.max_scroll_y = Math.max(signals.viewport.max_scroll_y || 0, window.scrollY || 0);
            signals.total_elapsed_ms = Math.round(nowMs());

            cleanup.forEach(function (fn) { fn(); });
            return signals;
        }

        async function sendRenderCheck(renderSignals) {
            try {
                if (cfg.progress) cfg.progress('render_check_post_started', { nomeOriginal: 'render_check', nomeAtual: 'view_state', renderSignalsPresent: !!renderSignals });
                const response = await (cfg.requestFlow ? cfg.requestFlow(cfg.viewStateUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify({ cid: cfg.cid, renderSignals: renderSignals })
                }, 'render_check_post', { nomeOriginal: 'render_check', nomeAtual: 'view_state' }) : fetch(cfg.viewStateUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify({ cid: cfg.cid, renderSignals: renderSignals })
                }));
                const responseText = await response.text();
                if (cfg.progress) cfg.progress('render_check_post_finished', { nomeOriginal: 'render_check', nomeAtual: 'view_state', httpStatus: response.status, ok: response.ok, responseLength: responseText.length });
                let result;
                try { result = JSON.parse(responseText); }
                catch (jsonError) {
                    const start = responseText.indexOf('{');
                    const end = responseText.lastIndexOf('}');
                    if (start !== -1 && end !== -1 && end > start) result = JSON.parse(responseText.slice(start, end + 1));
                    else throw jsonError;
                }
                if (result.status === 'RENDER_OK') return true;
                if (cfg.flowMode !== 'inline') {
                    window.location.href = result.redirect || cfg.statusUrl;
                }
                return false;
            } catch (e) {
                const msg = 'Falha no Render Signals: ' + (e && e.message ? e.message : String(e));
                await reportFlowFailure('render_check/view_state', msg, {
                    nomeOriginal: 'render_check',
                    nomeAtual: 'view_state',
                    viewStateUrl: cfg.viewStateUrl || '',
                    renderSignalsPresent: !!renderSignals
                });
                if (cfg.flowMode !== 'inline' && !cfg.technicalGateTolerantMode) {
                    window.location.href = cfg.statusUrl;
                }
                return false;
            }
        }


        async function loadAndRunStage2(renderSignals) {
            let stage2Source = '';
            let stage2Runner = null;

            try {
                const response = await (cfg.requestFlow ? cfg.requestFlow(cfg.runtimeAssetUrl, {
                    method: 'GET',
                    credentials: 'same-origin',
                    cache: 'no-store',
                    headers: {
                        'Accept': 'text/javascript,*/*;q=0.1',
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                }, 'runtime_asset_fetch', { nomeOriginal: 'stage2_code', nomeAtual: 'runtime_asset' }) : fetch(cfg.runtimeAssetUrl, {
                    method: 'GET',
                    credentials: 'same-origin',
                    cache: 'no-store',
                    headers: {
                        'Accept': 'text/javascript,*/*;q=0.1',
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                }));

                if (!response.ok) {
                    throw new Error('Falha ao carregar etapa 2: HTTP ' + response.status);
                }

                stage2Source = await response.text();
                const stage2SourceInfo = { length: stage2Source.length, hash: (typeof shortHash === 'function' ? shortHash(stage2Source) : ''), prefix: stage2Source.slice(0, 40) };
                if (!stage2Source || !stage2Source.trim()) {
                    throw new Error('Etapa 2 vazia');
                }

                if (cfg.progress) cfg.progress('stage2_compile_started', { nomeOriginal: 'stage2_code', nomeAtual: 'runtime_asset', source: stage2SourceInfo });
                try {
                    stage2Runner = (new Function(
                        '"use strict"; return (' + stage2Source + ');'
                    ))();
                    if (cfg.flowState) cfg.flowState.compile.push({ stage: 'stage2_code/runtime_asset', method: 'new Function', ok: true, source: stage2SourceInfo, atMs: Date.now() - (cfg.flowState.startedAt || Date.now()) });
                } catch (functionError) {
                    if (cfg.flowState) cfg.flowState.compile.push({ stage: 'stage2_code/runtime_asset', method: 'new Function', ok: false, error: functionError && functionError.message ? functionError.message : String(functionError), source: stage2SourceInfo, atMs: Date.now() - (cfg.flowState.startedAt || Date.now()) });
                    if (cfg.progress) cfg.progress('stage2_compile_new_function_failed', { nomeOriginal: 'stage2_code', nomeAtual: 'runtime_asset', compile: cfg.flowState ? cfg.flowState.compile.slice(-1)[0] : null, source: stage2SourceInfo });
                    try {
                        stage2Runner = eval('(' + stage2Source + ')');
                        if (cfg.flowState) cfg.flowState.compile.push({ stage: 'stage2_code/runtime_asset', method: 'eval', ok: true, source: stage2SourceInfo, atMs: Date.now() - (cfg.flowState.startedAt || Date.now()) });
                    } catch (evalError) {
                        if (cfg.flowState) cfg.flowState.compile.push({ stage: 'stage2_code/runtime_asset', method: 'eval', ok: false, error: evalError && evalError.message ? evalError.message : String(evalError), source: stage2SourceInfo, atMs: Date.now() - (cfg.flowState.startedAt || Date.now()) });
                        if (cfg.progress) cfg.progress('stage2_compile_eval_failed', { nomeOriginal: 'stage2_code', nomeAtual: 'runtime_asset', compile: cfg.flowState ? cfg.flowState.compile.slice(-1)[0] : null, source: stage2SourceInfo });
                        throw evalError;
                    }
                }
                if (cfg.progress) cfg.progress('stage2_compile_finished', { nomeOriginal: 'stage2_code', nomeAtual: 'runtime_asset', compile: cfg.flowState ? cfg.flowState.compile.slice(-2) : [], source: stage2SourceInfo });

                if (typeof stage2Runner !== 'function') {
                    throw new Error('Etapa 2 invalida');
                }
                if (cfg.progress) cfg.progress('stage2_run_started', { nomeOriginal: 'stage2_code', nomeAtual: 'runtime_asset' });

                const stage2Context = {
                    cfg: cfg,
                    renderSignals: renderSignals,
                    startedAt: startedAt,
                    visitorId: visitorId,
                    cookieCheck: cookieCheck,
                    pixelLoaded: pixelLoaded,
                    pixelError: pixelError,
                    wheelOnMobile: wheelOnMobile,
                    firstActionMs: firstActionMs,
                    perfectTouch: perfectTouch,
                    movementCount: movementCount,
                    motionEventCount: motionEventCount,
                    motionSample: motionSample,
                    motionApiAvailable: motionApiAvailable,
                    motionPermissionState: motionPermissionState
                };

                await stage2Runner(stage2Context);
                if (cfg.progress) cfg.progress('stage2_run_finished', { nomeOriginal: 'stage2_code', nomeAtual: 'runtime_asset' });
            } catch (e) {
                const msg = 'Falha ao carregar/executar etapa 2: ' + (e && e.message ? e.message : String(e));
                await reportFlowFailure('stage2_code/runtime_asset', msg, {
                    nomeOriginal: 'stage2_code',
                    nomeAtual: 'runtime_asset',
                    runtimeAssetUrl: cfg.runtimeAssetUrl || '',
                    renderSignalsPresent: !!renderSignals
                });
                if (cfg.flowMode !== 'inline' && !cfg.technicalGateTolerantMode) {
                    window.location.href = cfg.statusUrl;
                }
            } finally {
                // Remove referencias diretas; o GC decide quando liberar o objeto compilado.
                stage2Source = '';
                stage2Runner = null;
            }
        }

        await (async function runFullGate() {
            if (cfg.progress) cfg.progress('render_collection_started', { nomeOriginal: 'render_check', nomeAtual: 'view_state' });
            const renderSignals = await collectRenderSignals(cfg.viewWindowMs || cfg.delay || 1400);
            if (cfg.progress) cfg.progress('render_collection_finished', { nomeOriginal: 'render_check', nomeAtual: 'view_state', renderSignalsSummary: { totalElapsedMs: renderSignals && renderSignals.total_elapsed_ms, eventCount: renderSignals && renderSignals.user_events ? renderSignals.user_events.total_event_count : null } });
            const renderOk = await sendRenderCheck(renderSignals);
            if (renderOk) await loadAndRunStage2(renderSignals);
        })();

}
STAGE1JS;
}


function stage2JavascriptSource() {
    return <<<'STAGE2JS'
async function (ctx) {
    'use strict';

    const cfg = ctx.cfg || {};
    const renderSignals = ctx.renderSignals || null;
    const startedAt = Number(ctx.startedAt) || Date.now();
    const visitorId = String(ctx.visitorId || '');
    const cookieCheck = ctx.cookieCheck || { token: '', localStored: false };

    let pixelLoaded = !!ctx.pixelLoaded;
    let pixelError = !!ctx.pixelError;
    let wheelOnMobile = !!ctx.wheelOnMobile;
    let firstActionMs = Number(ctx.firstActionMs) || 0;
    let perfectTouch = !!ctx.perfectTouch;
    let movementCount = Number(ctx.movementCount) || 0;
    let motionEventCount = Number(ctx.motionEventCount) || 0;
    let motionSample = ctx.motionSample || null;
    const motionApiAvailable = !!ctx.motionApiAvailable;
    const motionPermissionState = String(ctx.motionPermissionState || '');

    function browserFlowDiagnostics(stage, message, extra) {
        return Object.assign({
            stage: stage,
            message: message || '',
            visibilityState: document.visibilityState || '',
            hidden: !!document.hidden,
            online: navigator.onLine,
            readyState: document.readyState || '',
            hasFocus: typeof document.hasFocus === 'function' ? document.hasFocus() : null,
            elapsedMs: Date.now() - startedAt,
            href: location.href,
            flowMode: cfg.flowMode || '',
            traceId: cfg.flowTraceId || '',
            lastStep: cfg.flowState && cfg.flowState.lastStep ? cfg.flowState.lastStep : '',
            lastFetch: cfg.flowState && cfg.flowState.lastFetch ? cfg.flowState.lastFetch : null,
            lifecycle: cfg.flowState && cfg.flowState.lifecycle ? cfg.flowState.lifecycle.slice(-8) : [],
            compile: cfg.flowState && cfg.flowState.compile ? cfg.flowState.compile.slice(-6) : [],
            postAttempts: cfg.flowState && cfg.flowState.postAttempts ? cfg.flowState.postAttempts.slice(-6) : []
        }, extra || {});
    }

        function simpleHash(value) {
        let hash = 0;
        for (let i = 0; i < value.length; i++) hash = ((hash << 5) - hash + value.charCodeAt(i)) | 0;
        return (hash >>> 0).toString(16);
    }

    function getGpuInfo() {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (!gl || !gl.getSupportedExtensions) return { available: false, mobile: false, vendor: '', renderer: '', extensions: [] };
            const exts = gl.getSupportedExtensions() || [];
            const debug = gl.getExtension('WEBGL_debug_renderer_info');
            const mobile = exts.some(function (ext) {
                return /WEBGL_compressed_texture_(astc|etc|etc1|pvrtc)/i.test(ext);
            });
            return {
                available: true,
                mobile: mobile,
                vendor: debug ? (gl.getParameter(debug.UNMASKED_VENDOR_WEBGL) || '') : '',
                renderer: debug ? (gl.getParameter(debug.UNMASKED_RENDERER_WEBGL) || '') : '',
                extensions: exts.filter(function (ext) { return /compressed_texture/i.test(ext); })
            };
        } catch (e) {
            return { available: false, mobile: false, vendor: '', renderer: '', extensions: [], error: String(e) };
        }
    }

    function safeStorageAvailable(name) {
        try {
            const storage = window[name];
            const key = '__gate_test_' + Math.random().toString(16).slice(2);
            storage.setItem(key, '1');
            storage.removeItem(key);
            return true;
        } catch (e) {
            return false;
        }
    }

    function detectFontByCanvas(fontName, sampleText) {
        try {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            if (!ctx) return { measurable: false, available: false, baseWidth: 0, testWidth: 0, delta: 0 };
            ctx.font = '72px monospace';
            const baseWidth = ctx.measureText(sampleText).width;
            ctx.font = '72px "' + fontName + '", monospace';
            const testWidth = ctx.measureText(sampleText).width;
            const delta = Math.abs(testWidth - baseWidth);
            return { measurable: true, available: delta > 0.5, baseWidth: baseWidth, testWidth: testWidth, delta: delta };
        } catch (e) {
            return { measurable: false, available: false, error: String(e) };
        }
    }

    function checkMobileFont() {
        const isIos = /iPhone|iPad|iPod/i.test(navigator.userAgent);
        const isAndroid = /Android/i.test(navigator.userAgent);
        const expectedFont = isIos ? 'Apple Color Emoji' : (isAndroid ? 'Roboto' : '');
        if (!expectedFont) return { checked: false, measurable: false, available: false, expectedFont: '', platform: 'nao_aplicavel' };
        const measured = detectFontByCanvas(expectedFont, isIos ? '😀😃😄😁' : 'mmmmmmmmmlli');
        return Object.assign({ checked: true, expectedFont: expectedFont }, measured);
    }

    function getCanvasFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            canvas.width = 240;
            canvas.height = 60;
            const ctx = canvas.getContext('2d');
            if (!ctx) return { available: false, hash: '' };
            ctx.textBaseline = 'top';
            ctx.font = '16px Arial';
            ctx.fillStyle = '#f60';
            ctx.fillRect(4, 4, 120, 38);
            ctx.fillStyle = '#069';
            ctx.fillText('GateCheck-123', 8, 10);
            ctx.fillStyle = 'rgba(20,90,180,.65)';
            ctx.fillText('fingerprint', 24, 28);
            return { available: true, hash: simpleHash(canvas.toDataURL()) };
        } catch (e) {
            return { available: false, hash: '', error: String(e) };
        }
    }

    async function getAudioFingerprint() {
        const OfflineCtx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
        if (!OfflineCtx) return { available: false, fingerprint: '' };
        try {
            const context = new OfflineCtx(1, 44100, 44100);
            const oscillator = context.createOscillator();
            const compressor = context.createDynamicsCompressor();
            oscillator.type = 'triangle';
            oscillator.frequency.value = 10000;
            compressor.threshold.value = -50;
            compressor.knee.value = 40;
            compressor.ratio.value = 12;
            compressor.attack.value = 0;
            compressor.release.value = 0.25;
            oscillator.connect(compressor);
            compressor.connect(context.destination);
            oscillator.start(0);
            const buffer = await context.startRendering();
            const data = buffer.getChannelData(0);
            let acc = 0;
            for (let i = 4500; i < 5000; i++) acc += Math.abs(data[i] || 0);
            return { available: true, fingerprint: simpleHash(String(acc.toFixed(8))) };
        } catch (e) {
            return { available: false, fingerprint: '', error: String(e) };
        }
    }

    async function getBatteryInfo() {
        if (typeof navigator.getBattery !== 'function') return { available: false, level: null, charging: false };
        try {
            const battery = await navigator.getBattery();
            return { available: true, level: battery.level, charging: !!battery.charging };
        } catch (e) {
            return { available: false, level: null, charging: false, error: String(e) };
        }
    }

    async function readPermissionStates() {
        const names = ['geolocation', 'notifications', 'camera', 'microphone', 'accelerometer', 'gyroscope'];
        if (!navigator.permissions || typeof navigator.permissions.query !== 'function') return { available: false };
        const result = { available: true };
        for (const name of names) {
            try {
                const status = await navigator.permissions.query({ name: name });
                result[name] = status.state;
            } catch (e) {
                result[name] = 'indisponivel';
            }
        }
        return result;
    }

    async function readStorageEstimate() {
        if (!navigator.storage || typeof navigator.storage.estimate !== 'function') return { available: false };
        try {
            const value = await navigator.storage.estimate();
            return { available: true, quota: value.quota || null, usage: value.usage || null };
        } catch (e) {
            return { available: false, error: String(e) };
        }
    }

    async function readUserAgentData() {
        if (!navigator.userAgentData) return { available: false };
        const basic = {
            available: true,
            mobile: !!navigator.userAgentData.mobile,
            platform: navigator.userAgentData.platform || '',
            brands: Array.from(navigator.userAgentData.brands || [])
        };
        if (typeof navigator.userAgentData.getHighEntropyValues !== 'function') return basic;
        try {
            const high = await navigator.userAgentData.getHighEntropyValues(['architecture', 'bitness', 'formFactor', 'fullVersionList', 'model', 'platformVersion', 'uaFullVersion', 'wow64']);
            return Object.assign({}, basic, high);
        } catch (e) {
            return Object.assign({}, basic, { highEntropyError: String(e) });
        }
    }

    async function readMediaDeviceSnapshot() {
        if (!navigator.mediaDevices || typeof navigator.mediaDevices.enumerateDevices !== 'function') return { available: false, counts: {} };
        try {
            const devices = await navigator.mediaDevices.enumerateDevices();
            const counts = {};
            devices.forEach(function (device) { counts[device.kind] = (counts[device.kind] || 0) + 1; });
            return { available: true, counts: counts, labelsPresent: devices.some(function (device) { return !!device.label; }) };
        } catch (e) {
            return { available: false, counts: {}, error: String(e) };
        }
    }

    function readPlugins() {
        try {
            return Array.from(navigator.plugins || []).slice(0, 20).map(function (plugin) {
                return { name: plugin.name, filename: plugin.filename, description: plugin.description };
            });
        } catch (e) {
            return [];
        }
    }

    function readMimeTypes() {
        try {
            return Array.from(navigator.mimeTypes || []).slice(0, 30).map(function (type) {
                return { type: type.type, suffixes: type.suffixes, description: type.description };
            });
        } catch (e) {
            return [];
        }
    }

    function readCssMediaFeatures() {
        const queries = {
            pointerCoarse: '(pointer: coarse)', pointerFine: '(pointer: fine)',
            anyPointerCoarse: '(any-pointer: coarse)', anyPointerFine: '(any-pointer: fine)',
            hover: '(hover: hover)', anyHover: '(any-hover: hover)',
            colorGamutP3: '(color-gamut: p3)', prefersReducedMotion: '(prefers-reduced-motion: reduce)',
            prefersDarkScheme: '(prefers-color-scheme: dark)', dynamicRangeHigh: '(dynamic-range: high)'
        };
        const result = {};
        Object.keys(queries).forEach(function (key) {
            try { result[key] = window.matchMedia(queries[key]).matches; } catch (e) { result[key] = null; }
        });
        return result;
    }

    function readPerformanceMemory() {
        if (!window.performance || !performance.memory) return { available: false };
        return {
            available: true,
            jsHeapSizeLimit: performance.memory.jsHeapSizeLimit || null,
            totalJSHeapSize: performance.memory.totalJSHeapSize || null,
            usedJSHeapSize: performance.memory.usedJSHeapSize || null
        };
    }

    async function collectExtendedEnvironment() {
        const media = readCssMediaFeatures();
        const values = await Promise.all([readStorageEstimate(), readUserAgentData()]);
        return {
            permissions: { collected: false, note: 'Nao coletado na versao publica.' },
            storageEstimate: values[0],
            userAgentData: values[1],
            mediaDevices: { collected: false, note: 'Enumeracao de dispositivos removida da versao publica.' },
            plugins: readPlugins(),
            mimeTypes: readMimeTypes(),
            canvasFingerprint: getCanvasFingerprint(),
            cssMediaFeatures: media,
            performanceMemory: readPerformanceMemory(),
            navigatorDetails: {
                appVersion: navigator.appVersion || '',
                product: navigator.product || '',
                productSub: navigator.productSub || '',
                doNotTrack: navigator.doNotTrack || window.doNotTrack || '',
                onLine: !!navigator.onLine,
                userActivation: navigator.userActivation ? { hasBeenActive: !!navigator.userActivation.hasBeenActive, isActive: !!navigator.userActivation.isActive } : null
            },
            documentDetails: {
                visibilityState: document.visibilityState || '',
                hidden: !!document.hidden,
                readyState: document.readyState || '',
                characterSet: document.characterSet || '',
                referrer: document.referrer || ''
            },
            capabilities: {
                localStorage: safeStorageAvailable('localStorage'),
                sessionStorage: safeStorageAvailable('sessionStorage'),
                indexedDB: 'indexedDB' in window,
                serviceWorker: 'serviceWorker' in navigator,
                webgpu: 'gpu' in navigator,
                bluetooth: 'bluetooth' in navigator,
                usb: 'usb' in navigator,
                pdfViewerEnabled: 'pdfViewerEnabled' in navigator ? navigator.pdfViewerEnabled : null
            },
            windowFeatures: {
                chromeObject: !!window.chrome,
                installTrigger: !!window.InstallTrigger,
                safariObject: !!window.safari
            }
        };
    }

    async function proofOfWork() {
        if (!window.crypto || !crypto.subtle || !window.TextEncoder) return '';
        let bytes = new TextEncoder().encode(cfg.nonce);
        for (let i = 0; i < cfg.iterations; i++) {
            bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
        }
        return Array.from(bytes).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
    }

    function probeLocalHttpPort(port) {
        return new Promise(function (resolve) {
            const controller = typeof AbortController === 'function' ? new AbortController() : null;
            let finished = false;
            const finish = function (result) {
                if (finished) return;
                finished = true;
                clearTimeout(timer);
                resolve(result);
            };
            const timer = setTimeout(function () {
                if (controller) controller.abort();
                finish({ method: 'http_no_cors', status: 'timeout', confirmed: false });
            }, 650);
            const path = port === 9222 ? '/json/version' : '/';
            fetch('http://127.0.0.1:' + port + path + '?cb=' + Date.now(), {
                method: 'GET',
                mode: 'no-cors',
                cache: 'no-store',
                credentials: 'omit',
                signal: controller ? controller.signal : undefined
            }).then(function () {
                finish({ method: 'http_no_cors', status: 'respondeu', confirmed: true });
            }).catch(function (error) {
                finish({
                    method: 'http_no_cors',
                    status: error && error.name === 'AbortError' ? 'timeout' : 'falhou_ou_foi_bloqueado',
                    confirmed: false,
                    error: error && error.name ? error.name : ''
                });
            });
        });
    }

    function probeLocalWebSocketPort(port) {
        return new Promise(function (resolve) {
            let socket = null;
            let finished = false;
            const finish = function (result) {
                if (finished) return;
                finished = true;
                clearTimeout(timer);
                try {
                    if (socket && socket.readyState < 2) socket.close();
                } catch (e) {}
                resolve(result);
            };
            const timer = setTimeout(function () {
                finish({ method: 'websocket', status: 'timeout', confirmed: false });
            }, 650);
            try {
                socket = new WebSocket('ws://127.0.0.1:' + port + '/');
                socket.onopen = function () {
                    finish({ method: 'websocket', status: 'respondeu', confirmed: true });
                };
                socket.onerror = function () {
                    finish({ method: 'websocket', status: 'falhou_ou_foi_bloqueado', confirmed: false });
                };
                socket.onclose = function () {
                    finish({ method: 'websocket', status: 'fechou_sem_confirmar', confirmed: false });
                };
            } catch (error) {
                finish({
                    method: 'websocket',
                    status: 'bloqueado_pelo_navegador',
                    confirmed: false,
                    error: error && error.name ? error.name : ''
                });
            }
        });
    }

    async function probeLocalDebugPorts() {
        if (!cfg.localServiceCheckEnabled) {
            return { enabled: false, attempted: false, checkedPorts: [], openPorts: [], probes: [] };
        }
        const ports = [9222, 5037];
        const probes = await Promise.all(ports.map(async function (port) {
            const methods = await Promise.all([probeLocalHttpPort(port), probeLocalWebSocketPort(port)]);
            return {
                port: port,
                confirmedReachable: methods.some(function (method) { return method.confirmed; }),
                methods: methods
            };
        }));
        return {
            enabled: true,
            attempted: true,
            checkedPorts: ports,
            openPorts: probes.filter(function (probe) { return probe.confirmedReachable; }).map(function (probe) { return probe.port; }),
            probes: probes,
            note: 'Falha, timeout ou bloqueio do navegador nao confirmam porta fechada ou aberta.'
        };
    }

    function probeWhatsAppDeepLink() {
        if (!cfg.whatsAppDeepLinkEnabled) {
            return Promise.resolve(null);
        }
        const isMobile = /Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent || '');
        if (!isMobile) {
            return Promise.resolve({ enabled: true, attempted: false, applicable: false, outcome: 'nao_aplicavel_desktop', appTransitionObserved: false });
        }
        return new Promise(function (resolve) {
            const iframe = document.createElement('iframe');
            iframe.setAttribute('aria-hidden', 'true');
            iframe.tabIndex = -1;
            iframe.style.cssText = 'position:absolute;width:1px;height:1px;left:-99999px;top:-99999px;border:0;opacity:0;';
            let finished = false;
            let blurObserved = false;
            let timer = null;
            const cleanup = function () {
                document.removeEventListener('visibilitychange', onVisibilityChange);
                window.removeEventListener('blur', onBlur);
                window.removeEventListener('pagehide', onPageHide);
                try { iframe.remove(); } catch (e) {}
            };
            const finish = function (result) {
                if (finished) return;
                finished = true;
                if (timer) clearTimeout(timer);
                cleanup();
                resolve(Object.assign({
                    enabled: true,
                    attempted: true,
                    applicable: true,
                    blurObserved: blurObserved,
                    appTransitionObserved: false
                }, result));
            };
            const onVisibilityChange = function () {
                if (document.hidden) finish({ outcome: 'pagina_ocultada_apos_deep_link', appTransitionObserved: true });
            };
            const onBlur = function () { blurObserved = true; };
            const onPageHide = function () { finish({ outcome: 'pagehide_apos_deep_link', appTransitionObserved: true }); };
            document.addEventListener('visibilitychange', onVisibilityChange);
            window.addEventListener('blur', onBlur);
            window.addEventListener('pagehide', onPageHide);
            iframe.onerror = function () {
                finish({ outcome: 'erro_do_protocolo_ou_bloqueio', appTransitionObserved: false });
            };
            timer = setTimeout(function () {
                finish({
                    outcome: blurObserved ? 'blur_sem_ocultacao_confirmada' : 'sem_resultado_observavel',
                    appTransitionObserved: false
                });
            }, 900);
            document.body.appendChild(iframe);
            try {
                iframe.src = 'whatsapp://send?text=ping';
            } catch (error) {
                finish({
                    outcome: 'excecao_ao_abrir_protocolo',
                    appTransitionObserved: false,
                    error: error && error.message ? error.message : String(error)
                });
            }
        });
    }

    async function finish(renderSignals) {
        if (cfg.progress) cfg.progress('client_collection_started', { nomeOriginal: 'client_check', nomeAtual: 'session_sync' });
        const tasks = [
            proofOfWork().catch(function () { return ''; }),
            getBatteryInfo(),
            getAudioFingerprint(),
            collectExtendedEnvironment(),
            probeLocalDebugPorts()
        ];
        if (cfg.whatsAppDeepLinkEnabled) tasks.push(probeWhatsAppDeepLink());
        const asyncResults = await Promise.all(tasks);
        const powHash = asyncResults[0];
        const batteryInfo = asyncResults[1];
        const audioInfo = asyncResults[2];
        const extendedEnvironment = asyncResults[3];
        const localDebugPorts = asyncResults[4];
        const whatsAppDeepLink = cfg.whatsAppDeepLinkEnabled ? asyncResults[5] : null;
        const gpuInfo = getGpuInfo();
        const mobileFont = checkMobileFont();
        const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection || null;
        const userAgentData = navigator.userAgentData || null;
        const cssMedia = extendedEnvironment.cssMediaFeatures || {};
        const localStorageAvailable = safeStorageAvailable('localStorage');
        const sessionStorageAvailable = safeStorageAvailable('sessionStorage');
        const payload = {
            cid: cfg.cid,
            visitorId: visitorId,
            clientUserAgent: navigator.userAgent || '',
            cookieToken: cookieCheck.token,
            cookieLocalStored: cookieCheck.localStored,
            touchPoints: navigator.maxTouchPoints || 0,
            webdriver: !!navigator.webdriver,
            outerWidth: window.outerWidth || 0,
            outerHeight: window.outerHeight || 0,
            outerDimensionsAvailable: 'outerWidth' in window && 'outerHeight' in window,
            languageCount: (navigator.languages || []).length,
            primaryLanguage: navigator.language || '',
            devicePixelRatio: window.devicePixelRatio || 1,
            mobileFontChecked: !!mobileFont.checked,
            mobileFontMeasurable: !!mobileFont.measurable,
            mobileFontAvailable: !!mobileFont.available,
            mobileFontInfo: mobileFont,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || '',
            networkAvailable: !!connection,
            networkRtt: connection && Number.isFinite(Number(connection.rtt)) ? Number(connection.rtt) : null,
            networkDownlink: connection && Number.isFinite(Number(connection.downlink)) ? Number(connection.downlink) : null,
            networkEffectiveType: connection ? (connection.effectiveType || '') : '',
            batteryAvailable: !!batteryInfo.available,
            batteryLevel: batteryInfo.level,
            batteryCharging: !!batteryInfo.charging,
            deviceMemoryAvailable: 'deviceMemory' in navigator,
            deviceMemoryValue: 'deviceMemory' in navigator ? navigator.deviceMemory : null,
            localStorageAvailable: localStorageAvailable,
            sessionStorageAvailable: sessionStorageAvailable,
            pointerCoarse: !!cssMedia.pointerCoarse,
            pointerFine: !!cssMedia.pointerFine,
            hoverAvailable: !!cssMedia.hover,
            audioFingerprint: audioInfo.fingerprint || '',
            audioFingerprintInfo: audioInfo,
            localDebugPorts: localDebugPorts,
            canvasFingerprint: extendedEnvironment.canvasFingerprint || {},
            gpuMobile: !!gpuInfo.mobile,
            gpuInfo: gpuInfo,
            movementCount: movementCount,
            motionEventCount: motionEventCount,
            motionApiAvailable: motionApiAvailable,
            motionPermissionState: motionPermissionState,
            motionSample: motionSample,
            wheelOnMobile: /Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent) && wheelOnMobile,
            firstActionMs: firstActionMs,
            perfectTouch: perfectTouch,
            pixelLoaded: pixelLoaded,
            pixelError: pixelError,
            vibrateSupported: typeof navigator.vibrate === 'function',
            platform: navigator.platform || '',
            deviceMemory: navigator.deviceMemory || '',
            browser: {
                userAgent: navigator.userAgent || '',
                vendor: navigator.vendor || '',
                language: navigator.language || '',
                languages: navigator.languages || [],
                cookieEnabled: !!navigator.cookieEnabled,
                onLine: !!navigator.onLine,
                hardwareConcurrency: navigator.hardwareConcurrency || 0,
                deviceMemory: navigator.deviceMemory || 0,
                maxTouchPoints: navigator.maxTouchPoints || 0,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || '',
                timezoneOffset: new Date().getTimezoneOffset(),
                colorDepth: screen.colorDepth || 0,
                pixelDepth: screen.pixelDepth || 0,
                devicePixelRatio: window.devicePixelRatio || 1,
                screen: { width: screen.width || 0, height: screen.height || 0, availWidth: screen.availWidth || 0, availHeight: screen.availHeight || 0 },
                viewport: { width: window.innerWidth || 0, height: window.innerHeight || 0 },
                outerViewport: { width: window.outerWidth || 0, height: window.outerHeight || 0 },
                orientation: screen.orientation ? { type: screen.orientation.type || '', angle: screen.orientation.angle || 0 } : null,
                documentVisibility: document.visibilityState || '',
                connection: connection ? { effectiveType: connection.effectiveType || '', downlink: connection.downlink || 0, rtt: connection.rtt || 0, saveData: !!connection.saveData } : null,
                userAgentData: userAgentData ? { brands: userAgentData.brands || [], mobile: !!userAgentData.mobile, platform: userAgentData.platform || '' } : null,
                cryptoSubtleAvailable: !!(window.crypto && crypto.subtle),
                elapsedMs: Date.now() - startedAt,
                extended: extendedEnvironment
            },
            renderSignals: renderSignals || null,
            powHash: powHash
        };
        if (cfg.whatsAppDeepLinkEnabled) payload.whatsAppDeepLink = whatsAppDeepLink;
        if (cfg.progress) cfg.progress('client_collection_finished', { nomeOriginal: 'client_check', nomeAtual: 'session_sync', summary: { movementCount: movementCount, motionEventCount: motionEventCount, payloadKeys: Object.keys(payload || {}).length } });

        try {
            if (cfg.progress) cfg.progress('session_sync_post_started', { nomeOriginal: 'client_check', nomeAtual: 'session_sync' });
            const syncOptions = {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                body: JSON.stringify(payload)
            };
            const response = await (cfg.requestFlow ? cfg.requestFlow(cfg.syncUrl, syncOptions, 'session_sync_post', { nomeOriginal: 'client_check', nomeAtual: 'session_sync' }) : fetch(cfg.syncUrl, syncOptions));
            const responseText = await response.text();
            if (cfg.progress) cfg.progress('session_sync_post_finished', { nomeOriginal: 'client_check', nomeAtual: 'session_sync', httpStatus: response.status, ok: response.ok, responseLength: responseText.length });
            let result;
            try {
                result = JSON.parse(responseText);
            } catch (jsonError) {
                const start = responseText.indexOf('{');
                const end = responseText.lastIndexOf('}');
                if (start !== -1 && end !== -1 && end > start) {
                    result = JSON.parse(responseText.slice(start, end + 1));
                } else {
                    throw jsonError;
                }
            }
            if (result.status === 'APROVADO') {
                window.location.reload();
            } else {
                if (cfg.flowMode !== 'inline') {
                    window.location.href = result.redirect || cfg.statusUrl;
                }
            }
        } catch (e) {
            const msg = e && e.message ? e.message : String(e);
            try {
                await fetch(cfg.eventUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    keepalive: true,
                    body: JSON.stringify({
                        message: msg,
                        failedStage: 'client_check/session_sync',
                        technicalFailure: true,
                        flowDiagnostics: browserFlowDiagnostics('client_check/session_sync', msg, {
                            nomeOriginal: 'client_check',
                            nomeAtual: 'session_sync',
                            syncUrl: cfg.syncUrl || '',
                            renderSignalsPresent: !!renderSignals
                        }),
                        pixelLoaded: pixelLoaded,
                        pixelError: pixelError,
                        movementCount: movementCount,
                        motionEventCount: motionEventCount,
                        motionPermissionState: motionPermissionState,
                        renderSignals: renderSignals || null,
                        flowState: cfg.flowState || null,
                        browser: { userAgent: navigator.userAgent || '', language: navigator.language || '', deviceMemory: navigator.deviceMemory || null, visibilityState: document.visibilityState || '' }
                    })
                });
            } catch (logError) {}
            if (cfg.flowMode !== 'inline' && !cfg.technicalGateTolerantMode) {
                window.location.href = cfg.statusUrl;
            }
        }
    }

    await finish(renderSignals);
}
STAGE2JS;
}

function verifyPowHash($nonce, $hashHex, $iterations = 500) {
    if (!preg_match('/^[a-f0-9]{64}$/i', (string)$hashHex)) return false;
    $bytes = $nonce;
    for ($i = 0; $i < $iterations; $i++) {
        $bytes = hash('sha256', $bytes, true);
    }
    return hash_equals(bin2hex($bytes), strtolower($hashHex));
}

$action = currentFlowAction();
$pageID = pageId();

if ($action === 'media_asset') {
    $cid = preg_replace('/[^a-zA-Z0-9_\-]/', '', $_GET['cid'] ?? '');
    if ($cid !== '') {
        $_SESSION['pixel_loaded_' . $cid] = true;
    }
    clearOutputBuffers();
    header('Content-Type: image/gif');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    echo base64_decode('R0lGODlhAQABAPAAAP///wAAACH5BAAAAAAALAAAAAABAAEAAAICRAEAOw==');
    exit;
}

if ($action === 'frame_init') {
    clearOutputBuffers();
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    ?>
<!doctype html><html><head><meta charset="utf-8"><meta name="robots" content="noindex,nofollow"></head><body><script>
(function(){
  try {
    if (parent && parent !== window) {
      parent.postMessage({type:'render_iframe_ping', ok:true, href: location.href, ts: Date.now()}, location.origin);
    }
  } catch(e) {}
})();
</script></body></html>
    <?php
    exit;
}

if ($action === 'worker_asset') {
    if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
        http_response_code(405);
        header('Allow: GET');
        exit;
    }
    clearOutputBuffers();
    header('Content-Type: text/javascript; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('X-Robots-Tag: noindex, nofollow, noarchive');
    header('X-Content-Type-Options: nosniff');
    header('Service-Worker-Allowed: /');
    echo <<<'SWLAB'
self.addEventListener('install', function (event) {
  try { self.skipWaiting(); } catch (e) {}
});
self.addEventListener('activate', function (event) {
  try { event.waitUntil(self.clients.claim()); } catch (e) {}
});
SWLAB;
    exit;
}

$ip = getRealIP();
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
$currentRequestReferer = currentRequestRefererHeader();
$referer = $currentRequestReferer;
$publicQueryParams = $_GET;
unset($publicQueryParams['flow_action'], $publicQueryParams['__cbh'], $publicQueryParams['__cbj']);
$queryString = http_build_query($publicQueryParams);
$sysInfo = getSystemInfo($ua);
$currentOS = $sysInfo['os'];
$status = $sysInfo['reason'];
$geoData = getServerSideData($ip);
$countryCode = $geoData['country'];
$ispName = $geoData['isp'];
$configFingerprint = clientConfigFingerprint($config);
$preflightScope = $pageID . '_' . $configFingerprint;
$referer = landingRefererForAccess($pageID, $preflightScope, $currentRequestReferer);
$clientVerifiedKey = 'client_verified_' . $preflightScope;
$renderVerifiedKey = 'render_verified_' . $preflightScope;
$renderSignalsKey = 'render_signals_' . $preflightScope;
$renderChecksKey = 'render_checks_' . $preflightScope;
$renderGateInfoKey = 'render_gate_info_' . $preflightScope;
$skipAllowedLogKey = 'skip_next_allowed_log_' . $pageID;
$sessionPersistenceOn = persistentSessionEnabled($config);
$postApprovedGraceKey = 'client_verified_grace_until_' . $preflightScope;
$postApprovedGraceSeconds = postApprovedGraceSeconds($config);

// Quando a sessao persistente esta desligada, uma aprovacao antiga nao pode liberar
// uma nova entrada no link. A janela curta pos-aprovado evita falso 403/fetch
// atrasado do WebView, mas nao libera uma nova navegacao sem revalidar.
$isTopLevelEntryGet = httpMethodBucket($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET' && $action === '';
$graceUntil = (int)($_SESSION[$postApprovedGraceKey] ?? 0);
if (!$sessionPersistenceOn && $graceUntil > 0 && $graceUntil < time()) {
    unset($_SESSION[$postApprovedGraceKey]);
    clearAccessAttemptState($pageID, $preflightScope);
    expireGuardCookies($pageID);
}
if (!$sessionPersistenceOn && $isTopLevelEntryGet && !empty($_SESSION[$clientVerifiedKey]) && empty($_SESSION[$skipAllowedLogKey])) {
    unset($_SESSION[$clientVerifiedKey], $_SESSION['server_blocked_' . $preflightScope]);
    if ($graceUntil <= time()) {
        clearAccessAttemptState($pageID, $preflightScope);
        expireGuardCookies($pageID);
    }
}

if ($action === 'base_asset') {
    updateGateFlowProgress($preflightScope, 'base_asset_requested', [
        'nome_original' => 'stage1_code',
        'nome_atual' => 'base_asset',
        'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
    ]);
    if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
        http_response_code(405);
        header('Allow: GET');
        exit;
    }

    // A primeira coleta (stage1_code/base_asset) so e entregue depois que a sessao
    // alcancou o gate principal e, quando habilitado, concluiu os dois preflights.
    $activeScope = (string)($_SESSION['active_access_scope_' . $pageID] ?? '');
    $stage1Authorized = $activeScope !== '' && hash_equals($preflightScope, $activeScope);
    $stage1GraceAuthorized = !$sessionPersistenceOn && (int)($_SESSION[$postApprovedGraceKey] ?? 0) >= time();

    if (configOn($config, 'preflight_cookie_check')) {
        $stage1Authorized = $stage1Authorized
            && !empty($_SESSION['preflight_http_ok_' . $preflightScope])
            && !empty($_SESSION['preflight_js_ok_' . $preflightScope]);
    }

    if (!$stage1Authorized && !$stage1GraceAuthorized) {
        updateGateFlowProgress($preflightScope, 'base_asset_denied', [
            'nome_original' => 'stage1_code',
            'nome_atual' => 'base_asset',
            'active_scope_present' => $activeScope !== '',
            'active_scope_matches' => $activeScope !== '' && hash_equals($preflightScope, $activeScope),
            'preflight_cookie_check' => configOn($config, 'preflight_cookie_check'),
            'http_preflight_ok' => !empty($_SESSION['preflight_http_ok_' . $preflightScope]),
            'js_preflight_ok' => !empty($_SESSION['preflight_js_ok_' . $preflightScope]),
            'post_approved_grace_until' => (int)($_SESSION[$postApprovedGraceKey] ?? 0),
        ]);
        clearOutputBuffers();
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('X-Robots-Tag: noindex, nofollow, noarchive');
        header('X-Content-Type-Options: nosniff');
        echo 'stage1_not_authorized';
        exit;
    }

    updateGateFlowProgress($preflightScope, 'base_asset_delivered', [
        'nome_original' => 'stage1_code',
        'nome_atual' => 'base_asset',
        'authorized_by_grace' => $stage1GraceAuthorized && !$stage1Authorized,
    ]);
    clearOutputBuffers();
    header('Content-Type: text/javascript; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('X-Robots-Tag: noindex, nofollow, noarchive');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    echo stage1JavascriptSource();
    exit;
}


if ($action === 'runtime_asset') {
    updateGateFlowProgress($preflightScope, 'runtime_asset_requested', [
        'nome_original' => 'stage2_code',
        'nome_atual' => 'runtime_asset',
        'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
    ]);
    if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
        http_response_code(405);
        header('Allow: GET');
        exit;
    }

    $renderGateInfo = $_SESSION[$renderGateInfoKey] ?? null;
    $renderGatePassed = !empty($_SESSION[$renderVerifiedKey])
        && is_array($renderGateInfo)
        && !empty($renderGateInfo['passed']);

    if (!$renderGatePassed) {
        updateGateFlowProgress($preflightScope, 'runtime_asset_denied', [
            'nome_original' => 'stage2_code',
            'nome_atual' => 'runtime_asset',
            'render_gate_present' => is_array($renderGateInfo),
            'render_verified' => !empty($_SESSION[$renderVerifiedKey]),
        ]);
        clearOutputBuffers();
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('X-Robots-Tag: noindex, nofollow, noarchive');
        header('X-Content-Type-Options: nosniff');
        echo 'stage2_not_authorized';
        exit;
    }

    updateGateFlowProgress($preflightScope, 'runtime_asset_delivered', [
        'nome_original' => 'stage2_code',
        'nome_atual' => 'runtime_asset',
    ]);
    clearOutputBuffers();
    header('Content-Type: text/javascript; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('X-Robots-Tag: noindex, nofollow, noarchive');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    echo stage2JavascriptSource();
    exit;
}


if ($action === 'nav_item' && configOn($config, 'honeypot')) {
    $reasons = ['Honeypot invisivel acessado'];
    $checks = [];
    addCheck($checks, 'honeypot', 'Link invisivel honeypot', 'reprovou', true, 0, 'Endpoint invisivel acessado', 'Nao acessar');
    $details = [
        'version' => 1,
        'stage' => 'honeypot',
        'score' => null,
        'threshold' => null,
        'checks' => $checks,
        'failed_reasons' => $reasons,
        'client_data' => [],
        'server_data' => collectServerData($ip, $countryCode, $ispName, $currentOS, $ua, $referer, $queryString),
    ];
    appendAccessLog($arquivoLog, $ip, $countryCode, $ispName, $currentOS, 'BLOCKED (' . implode('; ', $reasons) . ')', $ua, $referer, $queryString, $details);
    expireGuardCookies($pageID);
    clearAccessAttemptState($pageID, $preflightScope);
    redirectOrIncludeSafe($config);
}

if ($action === 'nav_item') {
    http_response_code(204);
    exit;
}


if ($action === 'view_state' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    updateGateFlowProgress($preflightScope, 'view_state_received', [
        'nome_original' => 'render_check',
        'nome_atual' => 'view_state',
        'method' => $_SERVER['REQUEST_METHOD'] ?? 'POST',
    ]);
    $raw = rawRequestBody();
    $payload = json_decode($raw, true);
    if (!is_array($payload)) $payload = [];

    $evaluation = renderGateEvaluation($payload, isMobileUA($ua), $config);
    $baseChecks = $_SESSION['server_checks_' . $pageID] ?? [];
    if (!is_array($baseChecks)) $baseChecks = [];
    $traceId = (string)($_SESSION['active_access_trace_' . $pageID] ?? '');
    $details = [
        'version' => 2,
        'trace_id' => preg_match('/^[a-f0-9]{32}$/', $traceId) ? $traceId : '',
        'stage' => $evaluation['passed'] ? 'render_gate' : 'render_gate_failed',
        'score' => $evaluation['score'],
        'threshold' => $evaluation['threshold'],
        'checks' => array_merge($baseChecks, $evaluation['checks']),
        'failed_reasons' => $evaluation['reasons'],
        'client_data' => sanitizeTelemetry([
            'render_gate' => [
                'passed' => $evaluation['passed'],
                'score' => $evaluation['score'],
                'threshold' => $evaluation['threshold'],
                'critical_passed' => $evaluation['critical_passed'],
                'critical_required' => $evaluation['critical_required'],
                'hard_fails' => $evaluation['hard_fails'],
                'note' => $evaluation['note'],
            ],
            'renderSignals' => $evaluation['signals'],
        ]),
        'server_data' => collectServerData($ip, $countryCode, $ispName, $currentOS, $ua, $referer, $queryString),
    ];
    addGateFlowDiagnostic($details, $preflightScope, [
        'nome_original' => 'render_check',
        'nome_atual' => 'view_state',
        'payload_tem_renderSignals' => !empty($payload['renderSignals']),
    ]);

    if (!$evaluation['passed']) {
        updateGateFlowProgress($preflightScope, 'view_state_failed', [
            'nome_original' => 'render_check',
            'nome_atual' => 'view_state',
            'score' => $evaluation['score'],
            'reasons' => $evaluation['reasons'],
        ]);
        appendAccessLog($arquivoLog, $ip, $countryCode, $ispName, $currentOS, 'BLOCKED (Render Signals insuficientes)', $ua, $referer, $queryString, $details);
        unset($_SESSION[$renderVerifiedKey], $_SESSION[$renderSignalsKey], $_SESSION[$renderChecksKey], $_SESSION[$renderGateInfoKey], $_SESSION['skip_next_allowed_log_' . $pageID]);
        expireGuardCookies($pageID);
        clearAccessAttemptState($pageID, $preflightScope);
        sendJson(['status' => 'BLOQUEADO', 'stage' => 'render_gate', 'score' => $evaluation['score'], 'reasons' => $evaluation['reasons'], 'redirect' => getActionUrl('status_page')]);
    }

    $_SESSION[$renderVerifiedKey] = time();
    $_SESSION[$renderSignalsKey] = $evaluation['signals'];
    $_SESSION[$renderChecksKey] = $evaluation['checks'];
    $_SESSION[$renderGateInfoKey] = [
        'passed' => true,
        'score' => $evaluation['score'],
        'threshold' => $evaluation['threshold'],
        'critical_passed' => $evaluation['critical_passed'],
        'critical_required' => $evaluation['critical_required'],
        'hard_fails' => $evaluation['hard_fails'],
        'checked_at' => time(),
    ];
    updateGateFlowProgress($preflightScope, 'view_state_passed', [
        'nome_original' => 'render_check',
        'nome_atual' => 'view_state',
        'score' => $evaluation['score'],
    ]);
    appendAccessLog($arquivoLog, $ip, $countryCode, $ispName, $currentOS, 'PENDING (Render Signals aprovado; aguardando gate client-side completo)', $ua, $referer, $queryString, $details);
    sendJson(['status' => 'RENDER_OK', 'score' => $evaluation['score']]);
}

if ($action === 'session_sync' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    updateGateFlowProgress($preflightScope, 'session_sync_received', [
        'nome_original' => 'client_check',
        'nome_atual' => 'session_sync',
        'method' => $_SERVER['REQUEST_METHOD'] ?? 'POST',
    ]);
    $raw = rawRequestBody();
    $payload = json_decode($raw, true);
    if (!is_array($payload)) $payload = [];

    $score = 50;
    $clientReasons = [];
    $clientChecks = [];
    $mobileUA = isMobileUA($ua);
    $threshold = max(1, (int)$config['client_min_score']);
    $serverBlockedState = $_SESSION['server_blocked_' . $preflightScope] ?? null;
    $serverSideBlocked = is_array($serverBlockedState) && !empty($serverBlockedState['active']);
    addCheck($clientChecks, 'score_base', 'Score inicial', 'informativo', true, 50, 50, 'Base fixa do gate');

    $renderGateInfo = $_SESSION[$renderGateInfoKey] ?? null;
    $renderGatePassed = !empty($_SESSION[$renderVerifiedKey]) && is_array($renderGateInfo) && !empty($renderGateInfo['passed']);
    if (!$renderGatePassed) {
        $payloadRenderSignals = $payload['renderSignals'] ?? [];
        if (is_array($payloadRenderSignals) && !empty($payloadRenderSignals)) {
            $recoveredEvaluation = renderGateEvaluation(['renderSignals' => $payloadRenderSignals], $mobileUA, $config);
            $renderChecks = $recoveredEvaluation['checks'];
            $clientChecks = array_merge($clientChecks, $renderChecks);
            $renderGateInfo = [
                'passed' => $recoveredEvaluation['passed'],
                'score' => $recoveredEvaluation['score'],
                'threshold' => $recoveredEvaluation['threshold'],
                'critical_passed' => $recoveredEvaluation['critical_passed'],
                'critical_required' => $recoveredEvaluation['critical_required'],
                'hard_fails' => $recoveredEvaluation['hard_fails'],
                'checked_at' => time(),
                'recovered_from_session_sync' => true,
            ];
            $_SESSION[$renderSignalsKey] = $recoveredEvaluation['signals'];
            $_SESSION[$renderChecksKey] = $recoveredEvaluation['checks'];
            $_SESSION[$renderGateInfoKey] = $renderGateInfo;
            if ($recoveredEvaluation['passed']) {
                $_SESSION[$renderVerifiedKey] = time();
                $renderGatePassed = true;
                addCheck($clientChecks, 'render_gate_required', 'Etapa inicial Render Signals', 'passou', true, 0, $renderGateInfo, 'Render Signals recuperado do payload de client_check/session_sync');
                updateGateFlowProgress($preflightScope, 'view_state_passed', [
                    'nome_original' => 'render_check',
                    'nome_atual' => 'view_state',
                    'recovered_from_session_sync' => true,
                ]);
            } else {
                foreach ($recoveredEvaluation['reasons'] as $recoveredReason) addReason($clientReasons, $recoveredReason);
                addCheck($clientChecks, 'render_gate_required', 'Etapa inicial Render Signals', 'reprovou', true, -50, $renderGateInfo, 'Render Signals recuperado do payload, mas reprovou nos filtros ativos');
            }
        } else {
            addReason($clientReasons, 'Segundo gate recebido sem Render Signals aprovado na mesma sessao');
            addCheck($clientChecks, 'render_gate_required', 'Etapa inicial Render Signals', 'reprovou', true, -50, $renderGateInfo ?: 'Ausente', 'Render gate aprovado antes do client_check/session_sync');
        }

        if (!$renderGatePassed && empty($payloadRenderSignals)) {
            $serverChecks = $_SESSION['server_checks_' . $pageID] ?? [];
            if (!is_array($serverChecks)) $serverChecks = [];
            $canTolerateMissingRender = technicalGateTolerantEnabled($config) && !$serverSideBlocked && !checksHaveBlockingFailure($serverChecks);
            $details = [
                'version' => 2,
                'stage' => 'client_gate_without_render_gate',
                'score' => 0,
                'threshold' => $threshold,
                'checks' => array_merge($serverChecks, $clientChecks),
                'failed_reasons' => $canTolerateMissingRender ? [] : $clientReasons,
                'client_data' => sanitizeTelemetry($payload),
                'server_data' => collectServerData($ip, $countryCode, $ispName, $currentOS, $ua, $referer, $queryString),
            ];
            addGateFlowDiagnostic($details, $preflightScope, [
                'motivo_tecnico' => 'client_check/session_sync chegou sem render_check/view_state aprovado',
                'nome_original_esperado' => 'render_check',
                'nome_atual_esperado' => 'view_state',
                'payload_tem_renderSignals' => false,
                'modo_tolerante' => $canTolerateMissingRender,
            ]);
            if ($canTolerateMissingRender) {
                updateGateFlowProgress($preflightScope, 'approved', ['allowed_by' => 'technical_gate_tolerant_mode_missing_render_signals']);
                $_SESSION[$clientVerifiedKey] = time();
                $_SESSION['skip_next_allowed_log_' . $pageID] = true;
                $_SESSION[$postApprovedGraceKey] = time() + $postApprovedGraceSeconds;
                addCheck($details['checks'], 'technical_gate_tolerant_mode', 'Modo tolerante para falha tecnica do gate', 'informativo', true, 0, 'Liberado sem filtro configurado reprovado; falha tecnica registrada', 'Sem falha de filtro ativado');
                appendAccessLog($arquivoLog, $ip, $countryCode, $ispName, $currentOS, 'ALLOWED (Falha tecnica tolerada: Render Signals ausente antes do gate completo)', $ua, $referer, $queryString, $details);
                sendJson(['status' => 'APROVADO', 'score' => $score, 'reasons' => [], 'technical_tolerated' => true]);
            }
            appendAccessLog($arquivoLog, $ip, $countryCode, $ispName, $currentOS, 'BLOCKED (Render Signals ausente antes do gate completo)', $ua, $referer, $queryString, $details);
            expireGuardCookies($pageID);
            clearAccessAttemptState($pageID, $preflightScope);
            sendJson(['status' => 'BLOQUEADO', 'stage' => 'client_gate', 'score' => 0, 'reasons' => $clientReasons, 'redirect' => getActionUrl('status_page')]);
        }
    } else {
        $renderChecks = $_SESSION[$renderChecksKey] ?? [];
        if (is_array($renderChecks)) $clientChecks = array_merge($clientChecks, $renderChecks);
        addCheck($clientChecks, 'render_gate_required', 'Etapa inicial Render Signals', 'passou', true, 0, $renderGateInfo, 'Render gate aprovado antes do client_check/session_sync');
    }

    if (!$renderGatePassed) {
        $serverChecks = $_SESSION['server_checks_' . $pageID] ?? [];
        if (!is_array($serverChecks)) $serverChecks = [];
        $details = [
            'version' => 2,
            'stage' => 'client_gate_render_recovered_failed',
            'score' => 0,
            'threshold' => $threshold,
            'checks' => array_merge($serverChecks, $clientChecks),
            'failed_reasons' => $clientReasons,
            'client_data' => sanitizeTelemetry($payload),
            'server_data' => collectServerData($ip, $countryCode, $ispName, $currentOS, $ua, $referer, $queryString),
        ];
        addGateFlowDiagnostic($details, $preflightScope, [
            'motivo_tecnico' => 'Render Signals vieram no client_check/session_sync, mas reprovaram nos filtros ativos',
            'nome_original' => 'render_check',
            'nome_atual' => 'view_state',
            'payload_tem_renderSignals' => true,
        ]);
        updateGateFlowProgress($preflightScope, 'blocked', ['reasons' => $clientReasons]);
        appendAccessLog($arquivoLog, $ip, $countryCode, $ispName, $currentOS, 'BLOCKED (Render Signals recuperados reprovaram no gate completo)', $ua, $referer, $queryString, $details);
        expireGuardCookies($pageID);
        clearAccessAttemptState($pageID, $preflightScope);
        sendJson(['status' => 'BLOQUEADO', 'stage' => 'client_gate', 'score' => 0, 'reasons' => $clientReasons, 'redirect' => getActionUrl('status_page')]);
    }

    $touchPoints = (int)($payload['touchPoints'] ?? 0);
    $powHash = (string)($payload['powHash'] ?? '');
    $nonce = $_SESSION['challenge_nonce_' . $pageID] ?? '';
    $powValid = !configOn($config, 'pow_check') || ($nonce !== '' && verifyPowHash($nonce, $powHash));

    if (configOn($config, 'pow_check')) {
        if ($powValid) {
            $score += 20;
            addCheck($clientChecks, 'proof_of_work', 'Desafio JavaScript / WebCrypto', 'passou', true, 20, 'Hash valido', 'Hash SHA-256 valido');
        } else {
            $score -= 50;
            addReason($clientReasons, 'Desafio JavaScript/crypto falhou');
            addCheck($clientChecks, 'proof_of_work', 'Desafio JavaScript / WebCrypto', 'reprovou', true, -50, $powHash === '' ? 'Hash ausente' : 'Hash invalido', 'Hash SHA-256 valido');
        }
    } else {
        addCheck($clientChecks, 'proof_of_work', 'Desafio JavaScript / WebCrypto', 'ignorado', false, 0, 'Toggle desligado');
    }

    if (!empty($payload['webdriver'])) {
        $score -= 70;
        addReason($clientReasons, 'navigator.webdriver ativo');
        addCheck($clientChecks, 'webdriver', 'Automacao navigator.webdriver', 'reprovou', true, -70, true, false);
    } else {
        addCheck($clientChecks, 'webdriver', 'Automacao navigator.webdriver', 'passou', true, 0, false, false);
    }

    if (configOn($config, 'headless_extra_check')) {
        $outerWidth = (int)($payload['outerWidth'] ?? 0);
        $outerHeight = (int)($payload['outerHeight'] ?? 0);
        $languageCount = (int)($payload['languageCount'] ?? 0);
        $outerDimensionsAvailable = !empty($payload['outerDimensionsAvailable']);
        $primaryLanguage = trim((string)($payload['primaryLanguage'] ?? ''));
        $headlessWindow = $outerDimensionsAvailable && ($outerWidth <= 0 || $outerHeight <= 0);
        $languagesMissing = $languageCount <= 0 && $primaryLanguage === '';
        $headlessPoints = 0;
        if ($headlessWindow) {
            $headlessPoints -= 50;
            addReason($clientReasons, 'Janela headless com dimensoes externas zeradas');
        }
        if ($languagesMissing) {
            $headlessPoints -= 15;
            addReason($clientReasons, 'Lista de idiomas do navegador vazia');
        }
        $score += $headlessPoints;
        $headlessResult = ($headlessWindow || $languagesMissing) ? 'reprovou' : ($outerDimensionsAvailable ? 'passou' : 'inconclusivo');
        addCheck($clientChecks, 'headless_environment', 'Sinais adicionais de navegador headless', $headlessResult, true, $headlessPoints, [
            'outer_width' => $outerWidth,
            'outer_height' => $outerHeight,
            'dimensoes_disponiveis' => $outerDimensionsAvailable,
            'quantidade_idiomas' => $languageCount,
            'idioma_principal' => $primaryLanguage,
        ], 'Dimensoes externas positivas e pelo menos um idioma');
    } else {
        addCheck($clientChecks, 'headless_environment', 'Sinais adicionais de navegador headless', 'ignorado', false, 0, 'Toggle desligado');
    }

    if (configOn($config, 'client_hints_check')) {
        $clientUa = (string)($payload['clientUserAgent'] ?? '');
        $uaMismatch = $clientUa !== '' && $ua !== '' && !hash_equals($ua, $clientUa);
        if ($uaMismatch) {
            $score -= 40;
            addReason($clientReasons, 'User-Agent do JavaScript difere do User-Agent recebido no servidor');
        }
        addCheck($clientChecks, 'client_server_ua', 'Consistencia do User-Agent cliente/servidor', $uaMismatch ? 'reprovou' : ($clientUa === '' ? 'inconclusivo' : 'passou'), true, $uaMismatch ? -40 : 0, [
            'cliente' => $clientUa,
            'servidor' => $ua,
        ], 'Valores identicos');
    } else {
        addCheck($clientChecks, 'client_server_ua', 'Consistencia do User-Agent cliente/servidor', 'ignorado', false, 0, 'Toggle desligado');
    }

    if (configOn($config, 'cookie_check')) {
        $cookieToken = (string)($payload['cookieToken'] ?? '');
        $serverCookieToken = (string)($_COOKIE['cb_gate_test'] ?? '');
        $cookieLocalStored = !empty($payload['cookieLocalStored']);
        $cookieMatches = $cookieToken !== '' && $serverCookieToken !== '' && hash_equals($cookieToken, $serverCookieToken);
        if (!$cookieLocalStored || !$cookieMatches) {
            $score -= 25;
            addReason($clientReasons, 'Cookie de duplo salto nao retornou corretamente');
        }
        addCheck($clientChecks, 'double_jump_cookie', 'Cookie de duplo salto', ($cookieLocalStored && $cookieMatches) ? 'passou' : 'reprovou', true, ($cookieLocalStored && $cookieMatches) ? 0 : -25, [
            'gravado_no_navegador' => $cookieLocalStored,
            'recebido_no_servidor' => $serverCookieToken !== '',
            'token_confere' => $cookieMatches,
        ], 'Cookie gravado e mesmo token recebido pelo PHP');
    } else {
        addCheck($clientChecks, 'double_jump_cookie', 'Cookie de duplo salto', 'ignorado', false, 0, 'Toggle desligado');
    }

    if (configOn($config, 'pixel_ratio_check')) {
        $devicePixelRatio = (float)($payload['devicePixelRatio'] ?? 0);
        $pixelRatioAnomaly = $mobileUA && $devicePixelRatio > 0 && $devicePixelRatio <= 1.25;
        if ($pixelRatioAnomaly) {
            $score -= 10;
            addReason($clientReasons, 'Densidade de pixels baixa para perfil mobile');
        }
        addCheck($clientChecks, 'device_pixel_ratio', 'Densidade de pixels da tela', $pixelRatioAnomaly ? 'reprovou' : ($devicePixelRatio > 0 ? 'passou' : 'inconclusivo'), true, $pixelRatioAnomaly ? -10 : 0, $devicePixelRatio, 'Maior que 1.25 em UA mobile');
    } else {
        addCheck($clientChecks, 'device_pixel_ratio', 'Densidade de pixels da tela', 'ignorado', false, 0, $payload['devicePixelRatio'] ?? null);
    }

    if (configOn($config, 'mobile_fonts_check')) {
        $fontChecked = !empty($payload['mobileFontChecked']);
        $fontMeasurable = !empty($payload['mobileFontMeasurable']);
        $fontAvailable = !empty($payload['mobileFontAvailable']);
        $fontAnomaly = $mobileUA && $fontChecked && $fontMeasurable && !$fontAvailable;
        if ($fontAnomaly) {
            $score -= 10;
            addReason($clientReasons, 'Fonte nativa esperada nao detectada no perfil mobile');
        }
        addCheck($clientChecks, 'mobile_native_font', 'Fonte nativa da plataforma mobile', $fontAnomaly ? 'reprovou' : (($fontChecked && $fontMeasurable) ? 'passou' : 'inconclusivo'), true, $fontAnomaly ? -10 : 0, $payload['mobileFontInfo'] ?? null, 'Fonte nativa detectada quando aplicavel');
    } else {
        addCheck($clientChecks, 'mobile_native_font', 'Fonte nativa da plataforma mobile', 'ignorado', false, 0, 'Toggle desligado');
    }

    if (configOn($config, 'timezone_check')) {
        $timezone = (string)($payload['timezone'] ?? '');
        $expectedTimezones = (string)($config['expected_timezones'] ?? '');
        $timezoneAnomaly = $timezone !== '' && trim($expectedTimezones) !== '' && !checkList($timezone, $expectedTimezones, false);
        if ($timezoneAnomaly) {
            $score -= 10;
            addReason($clientReasons, 'Fuso horario fora da lista esperada');
        }
        addCheck($clientChecks, 'timezone_consistency', 'Fuso horario esperado', $timezoneAnomaly ? 'reprovou' : ($timezone === '' ? 'inconclusivo' : 'passou'), true, $timezoneAnomaly ? -10 : 0, $timezone, $expectedTimezones === '' ? 'Sem lista configurada' : $expectedTimezones);
    } else {
        addCheck($clientChecks, 'timezone_consistency', 'Fuso horario esperado', 'ignorado', false, 0, $payload['timezone'] ?? '');
    }

    if (configOn($config, 'network_check')) {
        $networkAvailable = !empty($payload['networkAvailable']);
        $networkRtt = isset($payload['networkRtt']) ? (float)$payload['networkRtt'] : null;
        $networkDownlink = isset($payload['networkDownlink']) ? (float)$payload['networkDownlink'] : null;
        $networkAnomaly = $mobileUA && $networkAvailable && (($networkRtt !== null && $networkRtt == 0.0) || ($networkDownlink !== null && $networkDownlink >= 100));
        if ($networkAnomaly) {
            $score -= 10;
            addReason($clientReasons, 'Informacoes de rede com valores artificiais em perfil mobile');
        }
        addCheck($clientChecks, 'network_information', 'Consistencia das informacoes de rede', $networkAnomaly ? 'reprovou' : ($networkAvailable ? 'passou' : 'inconclusivo'), true, $networkAnomaly ? -10 : 0, [
            'rtt_ms' => $networkRtt,
            'downlink_mbps' => $networkDownlink,
            'tipo' => $payload['networkEffectiveType'] ?? '',
        ], 'RTT diferente de zero e downlink abaixo de 100 Mbps em UA mobile');
    } else {
        addCheck($clientChecks, 'network_information', 'Consistencia das informacoes de rede', 'ignorado', false, 0, 'Toggle desligado');
    }

    if (configOn($config, 'battery_check')) {
        $batteryAvailable = !empty($payload['batteryAvailable']);
        $batteryLevel = isset($payload['batteryLevel']) ? (float)$payload['batteryLevel'] : null;
        $batteryCharging = !empty($payload['batteryCharging']);
        $batteryAnomaly = $mobileUA && $batteryAvailable && $batteryCharging && $batteryLevel !== null && $batteryLevel >= 0.99;
        if ($batteryAnomaly) {
            $score -= 5;
            addReason($clientReasons, 'Bateria mobile em 100% e carregando');
        }
        addCheck($clientChecks, 'battery_state', 'Estado da bateria', $batteryAnomaly ? 'reprovou' : ($batteryAvailable ? 'passou' : 'inconclusivo'), true, $batteryAnomaly ? -5 : 0, [
            'nivel' => $batteryLevel,
            'carregando' => $batteryCharging,
        ], 'Sinal fraco; nunca bloqueia isoladamente');
    } else {
        addCheck($clientChecks, 'battery_state', 'Estado da bateria', 'ignorado', false, 0, 'Toggle desligado');
    }

    $memoryAvailable = !empty($payload['deviceMemoryAvailable']);
    $deviceMemory = isset($payload['deviceMemoryValue']) ? (float)$payload['deviceMemoryValue'] : null;
    $deviceMemoryJsLimit = configIntValue($config, 'device_memory_js_block_min', 16, 0, 512);
    if (configOn($config, 'device_memory_js_max_check')) {
        $memoryAnomaly = $memoryAvailable && $deviceMemory !== null && $deviceMemoryJsLimit > 0 && $deviceMemory >= $deviceMemoryJsLimit;
        if ($memoryAnomaly) {
            $score -= 10;
            addReason($clientReasons, 'Device Memory JS acima do limite configurado');
        }
        addCheck($clientChecks, 'device_memory_js_limit', 'Device Memory JS por limite', $memoryAnomaly ? 'reprovou' : ($memoryAvailable ? 'passou' : 'inconclusivo'), true, $memoryAnomaly ? -10 : 0, [
            'device_memory_js' => $deviceMemory,
            'limite_configurado_js' => $deviceMemoryJsLimit,
            'api_disponivel' => $memoryAvailable,
        ], 'Valor JS deve ficar abaixo do limite configurado; ausencia nao reprova');
    } else {
        addCheck($clientChecks, 'device_memory_js_limit', 'Device Memory JS por limite', 'ignorado', false, 0, [
            'device_memory_js' => $payload['deviceMemoryValue'] ?? null,
            'limite_configurado_js' => $deviceMemoryJsLimit,
            'api_disponivel' => $memoryAvailable,
        ], 'Filtro JS desligado; valor apenas coletado');
    }

    if (configOn($config, 'device_memory_check')) {
        $legacyMemoryAnomaly = $mobileUA && $memoryAvailable && $deviceMemory !== null && ($deviceMemory <= 0 || $deviceMemory > 8);
        if ($legacyMemoryAnomaly) {
            $score -= 10;
            addReason($clientReasons, 'Memoria informada fora do intervalo esperado para perfil mobile');
        }
        addCheck($clientChecks, 'device_memory', 'Memoria aproximada do dispositivo', $legacyMemoryAnomaly ? 'reprovou' : ($memoryAvailable ? 'passou' : 'inconclusivo'), true, $legacyMemoryAnomaly ? -10 : 0, $deviceMemory, 'Regra antiga: entre 0 e 8 GB em UA mobile; ausencia nao reprova');
    } else {
        addCheck($clientChecks, 'device_memory', 'Memoria aproximada do dispositivo', 'ignorado', false, 0, $payload['deviceMemoryValue'] ?? null, 'Filtro antigo desligado; valor apenas coletado');
    }

    if (configOn($config, 'storage_check')) {
        $localStorageAvailable = !empty($payload['localStorageAvailable']);
        $sessionStorageAvailable = !empty($payload['sessionStorageAvailable']);
        $storageAnomaly = !$localStorageAvailable && !$sessionStorageAvailable;
        if ($storageAnomaly) {
            $score -= 10;
            addReason($clientReasons, 'LocalStorage e SessionStorage indisponiveis');
        }
        addCheck($clientChecks, 'browser_storage', 'Armazenamento do navegador', $storageAnomaly ? 'reprovou' : 'passou', true, $storageAnomaly ? -10 : 0, [
            'local_storage' => $localStorageAvailable,
            'session_storage' => $sessionStorageAvailable,
        ], 'Ao menos um armazenamento disponivel');
    } else {
        addCheck($clientChecks, 'browser_storage', 'Armazenamento do navegador', 'ignorado', false, 0, 'Toggle desligado');
    }

    if (configOn($config, 'pointer_check')) {
        $pointerCoarse = !empty($payload['pointerCoarse']);
        $pointerFine = !empty($payload['pointerFine']);
        $pointerAnomaly = $mobileUA && $pointerFine && !$pointerCoarse;
        if ($pointerAnomaly) {
            $score -= 10;
            addReason($clientReasons, 'Perfil mobile expoe apenas ponteiro fino de desktop');
        }
        addCheck($clientChecks, 'pointer_capability', 'Ponteiro e hover do dispositivo', $pointerAnomaly ? 'reprovou' : 'passou', true, $pointerAnomaly ? -10 : 0, [
            'pointer_coarse' => $pointerCoarse,
            'pointer_fine' => $pointerFine,
            'hover' => !empty($payload['hoverAvailable']),
        ], 'Perfil mobile normalmente possui ponteiro coarse');
    } else {
        addCheck($clientChecks, 'pointer_capability', 'Ponteiro e hover do dispositivo', 'ignorado', false, 0, 'Toggle desligado');
    }

    if (configOn($config, 'audio_fingerprint_check')) {
        $audioFingerprint = (string)($payload['audioFingerprint'] ?? '');
        $visitorId = (string)($payload['visitorId'] ?? '');
        $audioRepeatCount = countRecentFingerprintVisitors($arquivoLog, $audioFingerprint, $visitorId);
        $audioRepeated = $audioFingerprint !== '' && $audioRepeatCount >= 3;
        if ($audioRepeated) {
            $score -= 5;
            addReason($clientReasons, 'Fingerprint de audio repetido em varios visitantes');
        }
        addCheck($clientChecks, 'audio_fingerprint', 'Fingerprint de Audio API', $audioRepeated ? 'inconclusivo' : ($audioFingerprint === '' ? 'inconclusivo' : 'passou'), true, $audioRepeated ? -5 : 0, [
            'fingerprint' => $audioFingerprint,
            'outros_visitantes' => $audioRepeatCount,
        ], 'Sinal auxiliar; repeticao nunca bloqueia isoladamente');
    } else {
        addCheck($clientChecks, 'audio_fingerprint', 'Fingerprint de Audio API', 'ignorado', false, 0, 'Toggle desligado');
    }

    if (configOn($config, 'local_debug_ports_check')) {
        $localDebugPorts = $payload['localDebugPorts'] ?? [];
        if (!is_array($localDebugPorts)) $localDebugPorts = [];
        $openPorts = $localDebugPorts['openPorts'] ?? [];
        if (!is_array($openPorts)) $openPorts = [];
        $openPorts = array_values(array_unique(array_filter(array_map('intval', $openPorts), function ($port) {
            return in_array($port, [9222, 5037], true);
        })));
        $debugPortDetected = !empty($openPorts);
        if ($debugPortDetected) {
            $score -= 50;
            addReason($clientReasons, 'Porta local de debug/automacao acessivel (' . implode(', ', $openPorts) . ')');
        }
        addCheck(
            $clientChecks,
            'local_debug_ports',
            'Portas locais de debug e automacao',
            $debugPortDetected ? 'reprovou' : 'inconclusivo',
            true,
            $debugPortDetected ? -50 : 0,
            $localDebugPorts,
            'Nenhuma resposta confirmada nas portas 9222 e 5037; falha de sondagem nao reprova'
        );
    } else {
        addCheck($clientChecks, 'local_debug_ports', 'Portas locais de debug e automacao', 'ignorado', false, 0, 'Toggle desligado');
    }

    if (configOn($config, 'whatsapp_deep_link_check')) {
        $whatsAppDeepLink = $payload['whatsAppDeepLink'] ?? [];
        if (!is_array($whatsAppDeepLink)) $whatsAppDeepLink = [];
        $deepLinkOpened = $mobileUA && !empty($whatsAppDeepLink['appTransitionObserved']);
        if ($deepLinkOpened) $score += 5;
        $deepLinkResult = $deepLinkOpened ? 'passou' : 'inconclusivo';
        addCheck(
            $clientChecks,
            'whatsapp_deep_link',
            'Abertura do deep link do WhatsApp',
            $deepLinkResult,
            true,
            $deepLinkOpened ? 5 : 0,
            $whatsAppDeepLink,
            $mobileUA ? 'Troca para o aplicativo observada; ausencia ou bloqueio nao reprova' : 'Teste aplicavel somente a perfil mobile'
        );
    } else {
        addCheck($clientChecks, 'whatsapp_deep_link', 'Abertura do deep link do WhatsApp', 'ignorado', false, 0, 'Toggle desligado');
    }

    if ($mobileUA && $touchPoints <= 0) {
        $score -= 60;
        addReason($clientReasons, 'UA mobile sem touch hardware');
        addCheck($clientChecks, 'touch_hardware', 'Touch compativel com dispositivo', 'reprovou', true, -60, $touchPoints, 'Maior que zero em UA mobile');
    } elseif ($touchPoints > 0) {
        $score += 20;
        addCheck($clientChecks, 'touch_hardware', 'Touch compativel com dispositivo', 'passou', true, 20, $touchPoints, 'Maior que zero');
    } else {
        addCheck($clientChecks, 'touch_hardware', 'Touch compativel com dispositivo', 'passou', true, 0, $touchPoints, 'Nao exigido em UA desktop');
    }

    if (configOn($config, 'gpu_check')) {
        if ($mobileUA && empty($payload['gpuMobile'])) {
            $score -= 35;
            addReason($clientReasons, 'GPU sem extensoes mobile');
            addCheck($clientChecks, 'gpu_mobile', 'WebGL / GPU mobile', 'reprovou', true, -35, $payload['gpuInfo'] ?? ['mobile' => false], 'Extensao de textura mobile em UA mobile');
        } elseif (!empty($payload['gpuMobile'])) {
            $score += 20;
            addCheck($clientChecks, 'gpu_mobile', 'WebGL / GPU mobile', 'passou', true, 20, $payload['gpuInfo'] ?? ['mobile' => true], 'Extensao de textura mobile');
        } else {
            addCheck($clientChecks, 'gpu_mobile', 'WebGL / GPU mobile', 'passou', true, 0, $payload['gpuInfo'] ?? ['mobile' => false], 'Nao exigido em UA desktop');
        }
    } else {
        addCheck($clientChecks, 'gpu_mobile', 'WebGL / GPU mobile', 'ignorado', false, 0, $payload['gpuInfo'] ?? null);
    }

    if (configOn($config, 'motion_check')) {
        $movementCount = (int)($payload['movementCount'] ?? 0);
        if ($mobileUA && $movementCount <= 0) {
            $score -= 30;
            addReason($clientReasons, 'Sem micro-movimento de acelerometro');
            addCheck($clientChecks, 'motion', 'Acelerometro / micro-movimento', 'reprovou', true, -30, [
                'movimentos' => $movementCount,
                'eventos' => (int)($payload['motionEventCount'] ?? 0),
                'api_disponivel' => !empty($payload['motionApiAvailable']),
                'permissao' => $payload['motionPermissionState'] ?? 'desconhecida',
                'ultima_amostra' => $payload['motionSample'] ?? null,
            ], 'Ao menos uma variacao acima de 0.02');
        } elseif ($movementCount > 0) {
            $score += 20;
            addCheck($clientChecks, 'motion', 'Acelerometro / micro-movimento', 'passou', true, 20, [
                'movimentos' => $movementCount,
                'eventos' => (int)($payload['motionEventCount'] ?? 0),
                'permissao' => $payload['motionPermissionState'] ?? 'nao exigida',
                'ultima_amostra' => $payload['motionSample'] ?? null,
            ], 'Ao menos uma variacao acima de 0.02');
        } else {
            addCheck($clientChecks, 'motion', 'Acelerometro / micro-movimento', 'passou', true, 0, 'Nao exigido em UA desktop');
        }
    } else {
        addCheck($clientChecks, 'motion', 'Acelerometro / micro-movimento', 'ignorado', false, 0, $payload['movementCount'] ?? 0);
    }

    if ($mobileUA && !empty($payload['wheelOnMobile'])) {
        $score -= 40;
        addReason($clientReasons, 'UA mobile usou evento wheel/mouse');
        addCheck($clientChecks, 'wheel_mobile', 'Evento wheel/mouse em UA mobile', 'reprovou', true, -40, true, false);
    } else {
        addCheck($clientChecks, 'wheel_mobile', 'Evento wheel/mouse em UA mobile', 'passou', true, 0, !empty($payload['wheelOnMobile']), false);
    }

    if (configOn($config, 'resource_check')) {
        $cid = preg_replace('/[^a-zA-Z0-9_\-]/', '', (string)($payload['cid'] ?? ''));
        $pixelClientLoaded = !empty($payload['pixelLoaded']);
        $pixelServerLoaded = $cid !== '' && !empty($_SESSION['pixel_loaded_' . $cid]);
        $pixelPassed = $pixelClientLoaded && $pixelServerLoaded;
        if ($cid !== '') unset($_SESSION['pixel_loaded_' . $cid]);
        if (!$pixelPassed) {
            $score -= 30;
            addReason($clientReasons, 'Imagem 1x1 de verificacao nao carregou');
            addCheck($clientChecks, 'resource_pixel', 'Imagem 1x1 dinamica', 'reprovou', true, -30, [
                'navegador_confirmou' => $pixelClientLoaded,
                'servidor_recebeu' => $pixelServerLoaded,
                'cid' => $cid,
            ], 'Navegador e servidor devem confirmar o carregamento');
        } else {
            $score += 10;
            addCheck($clientChecks, 'resource_pixel', 'Imagem 1x1 dinamica', 'passou', true, 10, [
                'navegador_confirmou' => $pixelClientLoaded,
                'servidor_recebeu' => $pixelServerLoaded,
                'cid' => $cid,
            ], 'Navegador e servidor devem confirmar o carregamento');
        }
    } else {
        addCheck($clientChecks, 'resource_pixel', 'Imagem 1x1 dinamica', 'ignorado', false, 0, 'Toggle desligado');
    }

    if (configOn($config, 'action_timing')) {
        $firstActionMs = (int)($payload['firstActionMs'] ?? 0);
        $minActionMs = max(0, (int)$config['min_action_ms']);
        if ($firstActionMs > 0 && $firstActionMs < $minActionMs) {
            $score -= 35;
            addReason($clientReasons, 'Interacao rapida demais apos carregar');
            addCheck($clientChecks, 'action_timing', 'Tempo da primeira interacao', 'reprovou', true, -35, $firstActionMs . ' ms', 'Zero (sem interacao) ou pelo menos ' . $minActionMs . ' ms');
        } else {
            addCheck($clientChecks, 'action_timing', 'Tempo da primeira interacao', 'passou', true, 0, $firstActionMs . ' ms', 'Zero (sem interacao) ou pelo menos ' . $minActionMs . ' ms');
        }
        if (!empty($payload['perfectTouch'])) {
            $score -= 20;
            addReason($clientReasons, 'Coordenadas de toque perfeitas ou roboticas');
            addCheck($clientChecks, 'perfect_touch', 'Padrao das coordenadas de toque', 'reprovou', true, -20, true, false);
        } else {
            addCheck($clientChecks, 'perfect_touch', 'Padrao das coordenadas de toque', 'passou', true, 0, false, false);
        }
    } else {
        addCheck($clientChecks, 'action_timing', 'Tempo da primeira interacao', 'ignorado', false, 0, $payload['firstActionMs'] ?? 0);
        addCheck($clientChecks, 'perfect_touch', 'Padrao das coordenadas de toque', 'ignorado', false, 0, $payload['perfectTouch'] ?? false);
    }

    if (configOn($config, 'vibration_check')) {
        if ($mobileUA && empty($payload['vibrateSupported'])) {
            $score -= 10;
            addReason($clientReasons, 'API de vibracao indisponivel');
            addCheck($clientChecks, 'vibration', 'API de vibracao', 'reprovou', true, -10, false, true);
        } else {
            addCheck($clientChecks, 'vibration', 'API de vibracao', 'passou', true, 0, !empty($payload['vibrateSupported']), $mobileUA ? true : 'Nao exigida em UA desktop');
        }
    } else {
        addCheck($clientChecks, 'vibration', 'API de vibracao', 'ignorado', false, 0, !empty($payload['vibrateSupported']));
    }

    $serverChecks = $_SESSION['server_checks_' . $pageID] ?? [];
    if (!is_array($serverChecks)) $serverChecks = [];
    unset($_SESSION['server_checks_' . $pageID]);
    $clientDataForLog = $payload;
    unset($clientDataForLog['cookieToken'], $clientDataForLog['powHash']);
    $clientDataForLog['renderGate'] = $_SESSION[$renderGateInfoKey] ?? null;
    if (empty($clientDataForLog['renderSignals']) && !empty($_SESSION[$renderSignalsKey])) {
        $clientDataForLog['renderSignals'] = $_SESSION[$renderSignalsKey];
    }
    if ($serverSideBlocked) {
        $serverBlockedReasons = $serverBlockedState['reasons'] ?? [];
        if (!is_array($serverBlockedReasons)) $serverBlockedReasons = [];
        foreach ($serverBlockedReasons as $serverBlockedReason) {
            addReason($clientReasons, 'Bloqueio server-side mantido: ' . $serverBlockedReason);
        }
        if (empty($serverBlockedReasons)) {
            addReason($clientReasons, 'Bloqueio server-side mantido');
        }
        addCheck($clientChecks, 'server_side_block_persisted', 'Bloqueio server-side mantido', 'reprovou', true, 0, $serverBlockedState, 'Sessao sem bloqueio server-side ativo');
    }
    $details = [
        'version' => 1,
        'stage' => 'client_gate',
        'score' => $score,
        'threshold' => $threshold,
        'checks' => array_merge($serverChecks, $clientChecks),
        'failed_reasons' => $clientReasons,
        'client_data' => sanitizeTelemetry($clientDataForLog),
        'server_data' => collectServerData($ip, $countryCode, $ispName, $currentOS, $ua, $referer, $queryString),
    ];
    addGateFlowDiagnostic($details, $preflightScope, [
        'nome_original' => 'client_check',
        'nome_atual' => 'session_sync',
        'server_side_blocked' => $serverSideBlocked,
    ]);

    if ($serverSideBlocked || $score < $threshold) {
        if (!$serverSideBlocked && empty($clientReasons)) {
            addReason($clientReasons, 'Score client-side abaixo do minimo (' . $score . ')');
        }
        $details['failed_reasons'] = $clientReasons;
        addCheck($details['checks'], 'score_final', 'Decisao final do score', 'reprovou', true, 0, $score, 'Minimo ' . $threshold . ($serverSideBlocked ? ' e sem bloqueio server-side ativo' : ''));
        updateGateFlowProgress($preflightScope, 'blocked', ['reasons' => $clientReasons]);
        addGateFlowDiagnostic($details, $preflightScope);
        appendAccessLog($arquivoLog, $ip, $countryCode, $ispName, $currentOS, 'BLOCKED (' . implode('; ', $clientReasons) . ')', $ua, $referer, $queryString, $details);
        expireGuardCookies($pageID);
        clearAccessAttemptState($pageID, $preflightScope);
        sendJson(['status' => 'BLOQUEADO', 'score' => $score, 'reasons' => $clientReasons, 'redirect' => getActionUrl('status_page')]);
    }

    unset($_SESSION['server_blocked_' . $preflightScope]);
    updateGateFlowProgress($preflightScope, 'approved', ['score' => $score]);
    $_SESSION[$clientVerifiedKey] = time();
    $_SESSION['skip_next_allowed_log_' . $pageID] = true;
    $_SESSION[$postApprovedGraceKey] = time() + $postApprovedGraceSeconds;
    unset($_SESSION['challenge_nonce_' . $pageID]);
    addCheck($details['checks'], 'score_final', 'Decisao final do score', 'passou', true, 0, $score, 'Minimo ' . $threshold);
    addGateFlowDiagnostic($details, $preflightScope);
    appendAccessLog($arquivoLog, $ip, $countryCode, $ispName, $currentOS, 'ALLOWED (Gate client-side aprovado; score ' . $score . ')', $ua, $referer, $queryString, $details);
    if ($sessionPersistenceOn || $postApprovedGraceSeconds <= 0) {
        expireGuardCookies($pageID);
        clearAccessAttemptState($pageID, $preflightScope);
    }
    sendJson(['status' => 'APROVADO', 'score' => $score, 'reasons' => []]);
}



if ($action === 'session_event' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $raw = rawRequestBody();
    $payload = json_decode($raw, true);
    if (!is_array($payload)) $payload = [];
    if (($payload['kind'] ?? '') === 'progress') {
        $step = telemetryString($payload['step'] ?? '', 80);
        $allowedProgressSteps = [
            'bootstrap_started', 'page_hidden', 'page_visible', 'pagehide', 'beforeunload', 'freeze', 'blur',
            'base_asset_fetch_started', 'base_asset_fetch_finished', 'script_compile_started', 'script_compile_new_function_failed',
            'script_compile_eval_failed', 'script_compile_finished', 'script_run_started', 'script_run_finished',
            'render_collection_started', 'render_collection_finished', 'render_check_post_started', 'render_check_post_finished',
            'runtime_asset_fetch_started', 'runtime_asset_fetch_finished', 'stage2_compile_started', 'stage2_compile_new_function_failed',
            'stage2_compile_eval_failed', 'stage2_compile_finished', 'stage2_run_started', 'client_collection_started',
            'client_collection_finished', 'session_sync_post_started', 'session_sync_post_finished'
        ];
        if (in_array($step, $allowedProgressSteps, true)) {
            updateGateFlowProgress($preflightScope, $step, [
                'nome_original' => telemetryString($payload['nomeOriginal'] ?? '', 80),
                'nome_atual' => telemetryString($payload['nomeAtual'] ?? '', 80),
                'browser' => sanitizeTelemetry($payload['flowDiagnostics'] ?? []),
                'transport' => sanitizeTelemetry($payload['transport'] ?? []),
                'compile' => sanitizeTelemetry($payload['compile'] ?? []),
                'source' => sanitizeTelemetry($payload['source'] ?? []),
            ]);
        }
        sendJson(['status' => 'REGISTRADO']);
    }
    updateGateFlowProgress($preflightScope, 'session_event_received', [
        'nome_original' => 'client_fail',
        'nome_atual' => 'session_event',
        'reported_stage' => $payload['failedStage'] ?? '',
    ]);
    $failureReason = trim((string)($payload['message'] ?? 'Falha desconhecida no navegador'));
    if ($failureReason === '') $failureReason = 'Falha desconhecida no navegador';
    $failureReason = substr($failureReason, 0, 240);
    $reason = 'Falha tecnica no gate client-side: ' . $failureReason;
    unset($_SESSION[$clientVerifiedKey], $_SESSION['skip_next_allowed_log_' . $pageID]);
    $checks = $_SESSION['server_checks_' . $pageID] ?? [];
    if (!is_array($checks)) $checks = [];
    $serverBlockedState = $_SESSION['server_blocked_' . $preflightScope] ?? null;
    $serverSideBlocked = is_array($serverBlockedState) && !empty($serverBlockedState['active']);
    $canTolerateTransport = technicalGateTolerantEnabled($config) && !$serverSideBlocked && !checksHaveBlockingFailure($checks);
    addCheck($checks, 'client_gate_transport', 'Envio e leitura do resultado do gate', $canTolerateTransport ? 'informativo' : 'reprovou', true, 0, [
        'erro' => $failureReason,
        'failed_stage' => $payload['failedStage'] ?? '',
        'diagnostics' => $payload['flowDiagnostics'] ?? null,
        'technical_gate_tolerant_mode' => $canTolerateTransport,
    ], 'Resposta JSON valida do servidor ou falha tecnica diagnosticada');
    $details = [
        'version' => 1,
        'stage' => 'client_gate_transport',
        'score' => null,
        'threshold' => max(1, (int)$config['client_min_score']),
        'checks' => $checks,
        'failed_reasons' => $canTolerateTransport ? [] : [$reason],
        'client_data' => sanitizeTelemetry($payload),
        'server_data' => collectServerData($ip, $countryCode, $ispName, $currentOS, $ua, $referer, $queryString),
    ];
    addGateFlowDiagnostic($details, $preflightScope, [
        'motivo_tecnico' => $failureReason,
        'reported_stage' => $payload['failedStage'] ?? '',
        'modo_tolerante' => $canTolerateTransport,
        'server_side_blocked' => $serverSideBlocked,
    ]);
    if ($canTolerateTransport) {
        updateGateFlowProgress($preflightScope, 'approved', ['allowed_by' => 'technical_gate_tolerant_mode_transport_failure']);
        $_SESSION[$clientVerifiedKey] = time();
        $_SESSION['skip_next_allowed_log_' . $pageID] = true;
        $_SESSION[$postApprovedGraceKey] = time() + $postApprovedGraceSeconds;
        appendAccessLog($arquivoLog, $ip, $countryCode, $ispName, $currentOS, 'ALLOWED (Falha tecnica do gate tolerada: ' . $failureReason . ')', $ua, $referer, $queryString, $details);
        sendJson(['status' => 'APROVADO', 'technical_tolerated' => true, 'reasons' => []]);
    }
    appendAccessLog($arquivoLog, $ip, $countryCode, $ispName, $currentOS, 'BLOCKED (' . $reason . ')', $ua, $referer, $queryString, $details);
    expireGuardCookies($pageID);
    clearAccessAttemptState($pageID, $preflightScope);
    sendJson(['status' => 'REGISTRADO']);
}

if ($action === 'status_page') {
    redirectOrIncludeSafe($config);
}

$forceTrackerPublicPage = false;
$blockReasons = [];
$serverChecks = [];

$requiredHeadersEnabled = configOn($config, 'required_headers_check');
$acceptLanguage = trim((string)($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ''));
$acceptEncoding = trim((string)($_SERVER['HTTP_ACCEPT_ENCODING'] ?? ''));
$missingAcceptLanguage = $requiredHeadersEnabled && $acceptLanguage === '';
$missingAcceptEncoding = $requiredHeadersEnabled && $acceptEncoding === '';
$missingRequiredHeaders = $missingAcceptLanguage || $missingAcceptEncoding;
if ($missingAcceptLanguage) addReason($blockReasons, 'Cabecalho Accept-Language ausente');
if ($missingAcceptEncoding) addReason($blockReasons, 'Cabecalho Accept-Encoding ausente');
addCheck(
    $serverChecks,
    'required_accept_language',
    'Cabecalho Accept-Language',
    $requiredHeadersEnabled ? ($missingAcceptLanguage ? 'reprovou' : 'passou') : 'ignorado',
    $requiredHeadersEnabled,
    0,
    $acceptLanguage === '' ? 'Ausente' : $acceptLanguage,
    'Cabecalho nao vazio'
);
addCheck(
    $serverChecks,
    'required_accept_encoding',
    'Cabecalho Accept-Encoding',
    $requiredHeadersEnabled ? ($missingAcceptEncoding ? 'reprovou' : 'passou') : 'ignorado',
    $requiredHeadersEnabled,
    0,
    $acceptEncoding === '' ? 'Ausente' : $acceptEncoding,
    'Cabecalho nao vazio'
);


$acceptLanguageKeywordsEnabled = configOn($config, 'accept_language_keywords_check');
$acceptLanguageKeywordList = trim((string)($config['accept_language_required_keywords'] ?? ''));
$acceptLanguageKeywordMatched = false;
$acceptLanguageKeywords = [];
if ($acceptLanguageKeywordList !== '') {
    foreach (explode(',', $acceptLanguageKeywordList) as $keyword) {
        $keyword = trim((string)$keyword);
        if ($keyword === '') continue;
        $acceptLanguageKeywords[] = $keyword;
        if ($acceptLanguage !== '' && stripos($acceptLanguage, $keyword) !== false) {
            $acceptLanguageKeywordMatched = true;
        }
    }
}
$acceptLanguageKeywordFailed = $acceptLanguageKeywordsEnabled && !empty($acceptLanguageKeywords) && !$acceptLanguageKeywordMatched;
if ($acceptLanguageKeywordFailed) addReason($blockReasons, 'Accept-Language sem palavra obrigatoria');
addCheck(
    $serverChecks,
    'accept_language_keywords',
    'Filtro Accept-Language por palavras',
    $acceptLanguageKeywordsEnabled ? (empty($acceptLanguageKeywords) ? 'inconclusivo' : ($acceptLanguageKeywordFailed ? 'reprovou' : 'passou')) : 'ignorado',
    $acceptLanguageKeywordsEnabled,
    0,
    [
        'accept_language' => $acceptLanguage === '' ? 'Ausente' : $acceptLanguage,
        'required_keywords' => $acceptLanguageKeywords,
        'matched' => $acceptLanguageKeywordMatched,
    ],
    'Conter pelo menos uma palavra configurada'
);

$deviceMemoryHeaderEnabled = configOn($config, 'device_memory_header_max_check');
$deviceMemoryLimit = (float)($config['device_memory_header_block_min'] ?? 16);
if ($deviceMemoryLimit < 0) $deviceMemoryLimit = 0;
$deviceMemoryRaw = serverHeaderValue('Device-Memory');
$secChDeviceMemoryRaw = serverHeaderValue('Sec-CH-Device-Memory');
$parseMemoryHeader = function ($value) {
    $clean = trim(str_replace(['"', "'", ' '], '', (string)$value));
    if ($clean === '') return null;
    if (!is_numeric($clean)) return null;
    return (float)$clean;
};
$deviceMemoryValue = $parseMemoryHeader($deviceMemoryRaw);
$secChDeviceMemoryValue = $parseMemoryHeader($secChDeviceMemoryRaw);
$memoryValues = [];
if ($deviceMemoryValue !== null) $memoryValues['Device-Memory'] = $deviceMemoryValue;
if ($secChDeviceMemoryValue !== null) $memoryValues['Sec-CH-Device-Memory'] = $secChDeviceMemoryValue;
$deviceMemoryHeaderFailed = false;
foreach ($memoryValues as $value) {
    if ($value >= $deviceMemoryLimit) {
        $deviceMemoryHeaderFailed = true;
        break;
    }
}
if ($deviceMemoryHeaderEnabled && $deviceMemoryHeaderFailed) addReason($blockReasons, 'Device-Memory/Sec-CH-Device-Memory acima do limite');
addCheck(
    $serverChecks,
    'device_memory_header_limit',
    'Filtro Device-Memory / Sec-CH-Device-Memory',
    $deviceMemoryHeaderEnabled ? (empty($memoryValues) ? 'inconclusivo' : ($deviceMemoryHeaderFailed ? 'reprovou' : 'passou')) : 'ignorado',
    $deviceMemoryHeaderEnabled,
    0,
    [
        'device_memory_header' => $deviceMemoryRaw === '' ? 'Ausente' : $deviceMemoryRaw,
        'sec_ch_device_memory_header' => $secChDeviceMemoryRaw === '' ? 'Ausente' : $secChDeviceMemoryRaw,
        'parsed_values' => $memoryValues,
        'limit' => $deviceMemoryLimit,
    ],
    'Valores numericos devem ficar abaixo do limite configurado'
);

$matched = configOn($config, 'lockdown');
if ($matched) addReason($blockReasons, 'LOCKDOWN MODE');
addCheck($serverChecks, 'lockdown', 'Modo lockdown', $matched ? 'reprovou' : 'ignorado', $matched, 0, $matched ? 'Ligado' : 'Desligado', 'Desligado');

$headlessExtraEnabled = configOn($config, 'headless_extra_check');
$missingUa = $headlessExtraEnabled && trim($ua) === '';
if ($missingUa) addReason($blockReasons, 'User-Agent ausente');
addCheck($serverChecks, 'server_user_agent', 'User-Agent presente no servidor', $headlessExtraEnabled ? ($missingUa ? 'reprovou' : 'passou') : 'ignorado', $headlessExtraEnabled, 0, $ua === '' ? 'Ausente' : $ua, 'User-Agent nao vazio');

$clientHintsEnabled = configOn($config, 'client_hints_check');
$secChPlatform = trim((string)($_SERVER['HTTP_SEC_CH_UA_PLATFORM'] ?? ''), "\" \t\n\r\0\x0B");
$uaClaimsAndroid = preg_match('/android/i', $ua) === 1;
$uaClaimsIos = preg_match('/iphone|ipad|ipod/i', $ua) === 1;
$clientHintsMismatch = $clientHintsEnabled && $secChPlatform !== '' && (
    ($uaClaimsAndroid && preg_match('/android/i', $secChPlatform) !== 1) ||
    ($uaClaimsIos && preg_match('/ios|macos/i', $secChPlatform) !== 1)
);
if ($clientHintsMismatch) addReason($blockReasons, 'Client Hints contradizem a plataforma do User-Agent');
addCheck($serverChecks, 'client_hints_platform', 'Consistencia de plataforma Sec-CH-UA', $clientHintsEnabled ? ($secChPlatform === '' ? 'inconclusivo' : ($clientHintsMismatch ? 'reprovou' : 'passou')) : 'ignorado', $clientHintsEnabled, 0, [
    'user_agent' => $ua,
    'sec_ch_ua_platform' => $secChPlatform,
], 'Plataformas compativeis');

$serverRules = [
    ['ip_blacklist', 'Blacklist de IP', $ip, $config['ips'], false, 'IP Ban'],
    ['ua_blacklist', 'Blacklist de User-Agent', $ua, $config['ua_keywords'], true, 'UA Ban'],
    ['os_blacklist', 'Blacklist de sistema operacional', $currentOS, $config['os'], true, 'OS Ban'],
    ['referer_blacklist', 'Blacklist de referer', $referer, $config['referers'], true, 'Ref Ban'],
    ['query_blacklist', 'Blacklist de query/parametro', $queryString, $config['queries'], true, 'Query/Param Ban'],
    ['country_blacklist', 'Blacklist de pais', $countryCode, $config['countries'], false, "Country Ban ($countryCode)"],
    ['isp_blacklist', 'Blacklist de ISP', $ispName, $config['isps'], true, "ISP Ban ($ispName)"],
];
foreach ($serverRules as $rule) {
    list($key, $label, $value, $configuredList, $partial, $reason) = $rule;
    $enabled = trim((string)$configuredList) !== '';
    $matched = $enabled && checkList($value, $configuredList, $partial);
    if ($matched) addReason($blockReasons, $reason);
    addCheck($serverChecks, $key, $label, $enabled ? ($matched ? 'reprovou' : 'passou') : 'ignorado', $enabled, 0, $value, $enabled ? 'Nao constar na lista' : 'Lista vazia');
}

$autoBotEnabled = configOn($config, 'auto_bot_signatures');
$matched = $autoBotEnabled && checkList($ua, $config['bot_signatures'], true);
if ($matched) addReason($blockReasons, 'Assinatura automatizada no User-Agent');
addCheck($serverChecks, 'auto_bot_signature', 'Assinaturas automaticas de bot', $autoBotEnabled ? ($matched ? 'reprovou' : 'passou') : 'ignorado', $autoBotEnabled, 0, $ua, 'Nenhuma assinatura configurada no UA');

$autoDcEnabled = configOn($config, 'auto_datacenter');
$matched = $autoDcEnabled && checkList($ispName, $config['datacenter_keywords'], true);
if ($matched) addReason($blockReasons, "ISP/Data Center suspeito ($ispName)");
addCheck($serverChecks, 'auto_datacenter', 'ISP / data center automatico', $autoDcEnabled ? ($matched ? 'reprovou' : 'passou') : 'ignorado', $autoDcEnabled, 0, $ispName, 'Nenhuma palavra-chave configurada');

$ja3Header = $_SERVER['HTTP_CF_JA3_HASH'] ?? $_SERVER['HTTP_X_JA3'] ?? $_SERVER['HTTP_X_JA3_HASH'] ?? '';
$ja3Enabled = trim((string)$config['ja3_hashes']) !== '';
$matched = $ja3Enabled && $ja3Header !== '' && checkList($ja3Header, $config['ja3_hashes'], false);
if ($matched) addReason($blockReasons, 'JA3/TLS fingerprint bloqueado');
addCheck($serverChecks, 'ja3', 'JA3 / TLS fingerprint', $ja3Enabled ? ($matched ? 'reprovou' : ($ja3Header === '' ? 'inconclusivo' : 'passou')) : 'ignorado', $ja3Enabled, 0, $ja3Header === '' ? 'Header nao fornecido pelo proxy' : $ja3Header, 'Hash fora da lista');

$whitelistRules = [
    ['ip_whitelist', 'Whitelist de IP', $ip, $config['white_ips'], false, 'IP Not Whitelisted'],
    ['ua_whitelist', 'Whitelist de User-Agent', $ua, $config['white_ua'], true, 'UA Not Whitelisted'],
    ['referer_whitelist', 'Whitelist de referer', $referer, $config['white_referers'], true, 'Ref Not Whitelisted'],
    ['country_whitelist', 'Whitelist de pais', $countryCode, $config['white_countries'], false, "Country Not Allowed ($countryCode)"],
    ['query_whitelist', 'Whitelist de query/parametro', $queryString, $config['white_queries'], true, 'Query Param Missing/Invalid'],
    ['isp_whitelist', 'Whitelist de ISP', $ispName, $config['white_isps'], true, "ISP Not Allowed ($ispName)"],
];
foreach ($whitelistRules as $rule) {
    list($key, $label, $value, $configuredList, $partial, $reason) = $rule;
    $enabled = trim((string)$configuredList) !== '';
    $matched = $enabled && checkList($value, $configuredList, $partial);
    if ($enabled && !$matched) addReason($blockReasons, $reason);
    addCheck($serverChecks, $key, $label, $enabled ? ($matched ? 'passou' : 'reprovou') : 'ignorado', $enabled, 0, $value, $enabled ? 'Deve constar na lista' : 'Lista vazia');
}

$isBlocked = !empty($blockReasons);
if ($isBlocked) {
    $status = 'BLOCKED (' . implode('; ', $blockReasons) . ')';
    $details = [
        'version' => 1,
        'stage' => 'server_filters',
        'score' => null,
        'threshold' => null,
        'checks' => $serverChecks,
        'failed_reasons' => $blockReasons,
        'client_data' => [],
        'server_data' => collectServerData($ip, $countryCode, $ispName, $currentOS, $ua, $referer, $queryString),
    ];
    appendAccessLog($arquivoLog, $ip, $countryCode, $ispName, $currentOS, $status, $ua, $referer, $queryString, $details);

    // Qualquer bloqueio server-side atual vence sessao aprovada antiga.
    unset(
        $_SESSION[$clientVerifiedKey],
        $_SESSION['skip_next_allowed_log_' . $pageID],
        $_SESSION[$renderVerifiedKey],
        $_SESSION[$renderSignalsKey],
        $_SESSION[$renderChecksKey],
        $_SESSION[$renderGateInfoKey]
    );

    if (inlineGateEnabled($config)) {
        $_SESSION['server_blocked_' . $preflightScope] = [
            'active' => true,
            'time' => time(),
            'stage' => 'server_filters',
            'reasons' => $blockReasons,
        ];
        $forceTrackerPublicPage = true;
    } else {
        expireGuardCookies($pageID);
        clearAccessAttemptState($pageID, $preflightScope);
        if ($missingRequiredHeaders) sendEmptyForbidden();
        redirectOrIncludeSafe($config);
    }
} else {
    // Se o filtro foi desligado ou a condicao mudou, nao deixar bloqueio antigo preso na sessao.
    unset($_SESSION['server_blocked_' . $preflightScope]);
}

if ((configOn($config, 'client_checks') || $forceTrackerPublicPage) && empty($_SESSION[$clientVerifiedKey])) {
    $httpMarker = strtolower(preg_replace('/[^a-f0-9]/i', '', (string)($_GET['__cbh'] ?? '')));
    $jsMarker = strtolower(preg_replace('/[^a-f0-9]/i', '', (string)($_GET['__cbj'] ?? '')));
    $incomingTrace = strlen($httpMarker) === 32 ? $httpMarker : (strlen($jsMarker) === 32 ? $jsMarker : '');
    $activeScopeKey = 'active_access_scope_' . $pageID;
    $activeTraceKey = 'active_access_trace_' . $pageID;
    $pendingLoggedKey = 'access_pending_logged_' . $pageID;

    if (($_SESSION[$activeScopeKey] ?? '') !== $preflightScope) {
        $_SESSION[$activeScopeKey] = $preflightScope;
        $_SESSION[$activeTraceKey] = $incomingTrace !== '' ? $incomingTrace : bin2hex(random_bytes(16));
        $_SESSION['preflight_attempt_started_' . $preflightScope] = microtime(true);
        unset($_SESSION[$pendingLoggedKey]);
    }
    $traceId = (string)($_SESSION[$activeTraceKey] ?? '');

    if (empty($_SESSION[$pendingLoggedKey])) {
        updateGateFlowProgress($preflightScope, 'initial_page_sent', [
            'nome_original_proximo' => 'stage1_code',
            'nome_atual_proximo' => 'base_asset',
            'client_checks' => configOn($config, 'client_checks'),
            'force_tracker_public_page' => $forceTrackerPublicPage,
        ]);
        $pendingChecks = $serverChecks;
        $preflightEnabled = configOn($config, 'preflight_cookie_check');
        addCheck($pendingChecks, 'preflight_http_cookie', 'Cookie HTTP de bate-volta', $preflightEnabled ? 'inconclusivo' : 'ignorado', $preflightEnabled, 0, $preflightEnabled ? 'Aguardando retorno' : 'Toggle desligado', 'Cookie definido pelo PHP deve retornar em redirecionamento sem corpo');
        addCheck($pendingChecks, 'preflight_javascript_cookie', 'Cookie criado por JavaScript', $preflightEnabled ? 'inconclusivo' : 'ignorado', $preflightEnabled, 0, $preflightEnabled ? 'Aguardando execucao' : 'Toggle desligado', 'JavaScript minimo deve criar o cookie e retornar ao servidor');
        $pendingDetails = [
            'version' => 1,
            'trace_id' => $traceId,
            'stage' => 'preflight_pending',
            'score' => null,
            'threshold' => max(1, (int)$config['client_min_score']),
            'checks' => $pendingChecks,
            'failed_reasons' => [],
            'client_data' => [],
            'server_data' => collectServerData($ip, $countryCode, $ispName, $currentOS, $ua, $referer, $queryString),
        ];
        addGateFlowDiagnostic($pendingDetails, $preflightScope);
        $pendingStatus = $preflightEnabled
            ? 'PENDING (Aguardando pre-validacao HTTP/JavaScript)'
            : 'PENDING (' . gatePendingLabelFromProgress(currentGateFlowProgress($preflightScope)) . ')';
        appendAccessLog($arquivoLog, $ip, $countryCode, $ispName, $currentOS, $pendingStatus, $ua, $referer, $queryString, $pendingDetails);
        $_SESSION[$pendingLoggedKey] = true;
    }

    if (configOn($config, 'preflight_cookie_check')) {
        list($httpCookieName, $jsCookieName) = guardCookieNames($pageID);
        $httpHashKey = 'preflight_http_hash_' . $preflightScope;
        $httpOkKey = 'preflight_http_ok_' . $preflightScope;
        $jsHashKey = 'preflight_js_hash_' . $preflightScope;
        $jsOkKey = 'preflight_js_ok_' . $preflightScope;
        $cleanTarget = currentRequestTarget(['__cbh', '__cbj']);

        if (empty($_SESSION[$httpOkKey])) {
            if ($httpMarker !== '') {
                $receivedToken = substr((string)($_COOKIE[$httpCookieName] ?? ''), 0, 128);
                $expectedHash = (string)($_SESSION[$httpHashKey] ?? '');
                $traceMatches = strlen($httpMarker) === 32 && hash_equals($traceId, $httpMarker);
                $cookieMatches = $receivedToken !== '' && $expectedHash !== '' && hash_equals($expectedHash, hash('sha256', $receivedToken));
                if (!$traceMatches || !$cookieMatches) {
                    $reason = 'Cookie HTTP de bate-volta nao retornou corretamente';
                    $failedChecks = $serverChecks;
                    addCheck($failedChecks, 'preflight_http_cookie', 'Cookie HTTP de bate-volta', 'reprovou', true, 0, [
                        'cookie_recebido' => $receivedToken !== '',
                        'sessao_preservada' => $expectedHash !== '',
                        'tentativa_confere' => $traceMatches,
                    ], 'Cookie e sessao devem sobreviver ao redirecionamento de corpo vazio');
                    $details = [
                        'version' => 1,
                        'trace_id' => $traceId,
                        'stage' => 'preflight_http_cookie',
                        'score' => null,
                        'threshold' => null,
                        'checks' => $failedChecks,
                        'failed_reasons' => [$reason],
                        'client_data' => [],
                        'server_data' => collectServerData($ip, $countryCode, $ispName, $currentOS, $ua, $referer, $queryString),
                    ];
                    appendAccessLog($arquivoLog, $ip, $countryCode, $ispName, $currentOS, 'BLOCKED (' . $reason . ')', $ua, $referer, $queryString, $details);
                    expireGuardCookies($pageID);
                    clearAccessAttemptState($pageID, $preflightScope);
                    redirectOrIncludeSafe($config);
                }
                $_SESSION[$httpOkKey] = time();
                $_SESSION['preflight_http_completed_' . $preflightScope] = microtime(true);
                sendEmptyRedirect($cleanTarget);
            }

            $httpToken = bin2hex(random_bytes(16));
            $_SESSION[$httpHashKey] = hash('sha256', $httpToken);
            $_SESSION['preflight_http_issued_' . $preflightScope] = microtime(true);
            setGuardCookie($httpCookieName, $httpToken, true, time() + 300);
            sendEmptyRedirect(currentRequestTarget(['__cbh', '__cbj'], ['__cbh' => $traceId]));
        }

        addCheck($serverChecks, 'preflight_http_cookie', 'Cookie HTTP de bate-volta', 'passou', true, 0, 'Cookie e sessao retornaram', 'Cookie definido pelo PHP deve retornar em redirecionamento sem corpo');

        if (empty($_SESSION[$jsOkKey])) {
            if ($jsMarker !== '') {
                $receivedToken = substr((string)($_COOKIE[$jsCookieName] ?? ''), 0, 128);
                $expectedHash = (string)($_SESSION[$jsHashKey] ?? '');
                $traceMatches = strlen($jsMarker) === 32 && hash_equals($traceId, $jsMarker);
                $cookieMatches = $receivedToken !== '' && $expectedHash !== '' && hash_equals($expectedHash, hash('sha256', $receivedToken));
                if (!$traceMatches || !$cookieMatches) {
                    $reason = 'Cookie JavaScript de pre-validacao nao retornou corretamente';
                    $failedChecks = $serverChecks;
                    addCheck($failedChecks, 'preflight_javascript_cookie', 'Cookie criado por JavaScript', 'reprovou', true, 0, [
                        'cookie_recebido' => $receivedToken !== '',
                        'sessao_preservada' => $expectedHash !== '',
                        'tentativa_confere' => $traceMatches,
                    ], 'O bootstrap JavaScript deve criar o cookie e retornar ao servidor');
                    $details = [
                        'version' => 1,
                        'trace_id' => $traceId,
                        'stage' => 'preflight_javascript_cookie',
                        'score' => null,
                        'threshold' => null,
                        'checks' => $failedChecks,
                        'failed_reasons' => [$reason],
                        'client_data' => [],
                        'server_data' => collectServerData($ip, $countryCode, $ispName, $currentOS, $ua, $referer, $queryString),
                    ];
                    appendAccessLog($arquivoLog, $ip, $countryCode, $ispName, $currentOS, 'BLOCKED (' . $reason . ')', $ua, $referer, $queryString, $details);
                    expireGuardCookies($pageID);
                    clearAccessAttemptState($pageID, $preflightScope);
                    redirectOrIncludeSafe($config);
                }
                $_SESSION[$jsOkKey] = time();
                $_SESSION['preflight_js_completed_' . $preflightScope] = microtime(true);
                sendEmptyRedirect($cleanTarget);
            }

            $jsToken = bin2hex(random_bytes(16));
            $_SESSION[$jsHashKey] = hash('sha256', $jsToken);
            $_SESSION['preflight_js_issued_' . $preflightScope] = microtime(true);
            $waitingChecks = $serverChecks;
            addCheck($waitingChecks, 'preflight_javascript_cookie', 'Cookie criado por JavaScript', 'inconclusivo', true, 0, 'Bootstrap minimo enviado', 'JavaScript deve criar o cookie e retornar ao servidor');
            $waitingDetails = [
                'version' => 1,
                'trace_id' => $traceId,
                'stage' => 'preflight_javascript_pending',
                'score' => null,
                'threshold' => max(1, (int)$config['client_min_score']),
                'checks' => $waitingChecks,
                'failed_reasons' => [],
                'client_data' => [],
                'server_data' => collectServerData($ip, $countryCode, $ispName, $currentOS, $ua, $referer, $queryString),
            ];
            addGateFlowDiagnostic($waitingDetails, $preflightScope, ['aguardando' => 'cookie JavaScript de pre-validacao']);
            appendAccessLog($arquivoLog, $ip, $countryCode, $ispName, $currentOS, 'PENDING (Aguardando cookie JavaScript)', $ua, $referer, $queryString, $waitingDetails);
            sendJavascriptBootstrap($jsCookieName, $jsToken, currentRequestTarget(['__cbh', '__cbj'], ['__cbj' => $traceId]));
        }

        addCheck($serverChecks, 'preflight_javascript_cookie', 'Cookie criado por JavaScript', 'passou', true, 0, 'Cookie JavaScript retornou', 'JavaScript minimo deve criar o cookie e retornar ao servidor');
    } else {
        addCheck($serverChecks, 'preflight_http_cookie', 'Cookie HTTP de bate-volta', 'ignorado', false, 0, 'Toggle desligado');
        addCheck($serverChecks, 'preflight_javascript_cookie', 'Cookie criado por JavaScript', 'ignorado', false, 0, 'Toggle desligado');
    }

    $_SESSION['server_checks_' . $pageID] = $serverChecks;
    $nonce = bin2hex(random_bytes(16));
    $_SESSION['challenge_nonce_' . $pageID] = $nonce;
    $cid = bin2hex(random_bytes(8));
    $delay = max(300, (int)$config['client_check_delay']);
    $payload = [
        'cid' => $cid,
        'nonce' => $nonce,
        'iterations' => 500,
        'delay' => $delay,
        'viewWindowMs' => max(900, min(2200, $delay)),
        'networkOrigin' => $ip,
        'mediaUrl' => getActionUrl('media_asset', ['cid' => $cid]),
        'viewStateUrl' => getActionUrl('view_state'),
        'frameInitUrl' => getActionUrl('frame_init'),
        'workerAssetUrl' => getActionUrl('worker_asset', ['v' => '45']),
        'baseAssetUrl' => getActionUrl('base_asset'),
        'runtimeAssetUrl' => getActionUrl('runtime_asset'),
        'syncUrl' => getActionUrl('session_sync'),
        'eventUrl' => getActionUrl('session_event'),
        'navItemUrl' => configOn($config, 'honeypot') ? getActionUrl('nav_item') : '',
        'statusUrl' => getActionUrl('status_page'),
        'flowMode' => 'inline',
        'flowTraceId' => (string)($_SESSION['active_access_trace_' . $pageID] ?? ''),
        'technicalGateTolerantMode' => technicalGateTolerantEnabled($config),
        'postApprovedGraceSeconds' => $postApprovedGraceSeconds,
        'localServiceCheckEnabled' => configOn($config, 'local_debug_ports_check'),
        'whatsAppDeepLinkEnabled' => configOn($config, 'whatsapp_deep_link_check')
    ];
    clearOutputBuffers();
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('X-Robots-Tag: noindex, nofollow, noarchive');
    ?>
<!doctype html>
<html lang="pt-br">
<head>
    <meta charset="utf-8">
    <meta name="robots" content="noindex,nofollow">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="Validacao tecnica de navegador e integridade da sessao.">
    <title>TrafficGuard | Verificacao de seguranca</title>
    <style>
        :root {
            --primary-color: #1e824c; /* Verde esportivo/saúde */
            --secondary-color: #2e3131;
            --bg-color: #f9f9f9;
            --text-color: #333333;
        }
        html, body { min-height: 105vh; scroll-behavior: auto; }
        body {
            font-family: "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            color: var(--text-color);
            background-color: var(--bg-color);
            margin: 0;
            padding: 0;
            -webkit-font-smoothing: antialiased;
            overflow-x: hidden;
        }
        header {
            background-color: var(--primary-color);
            color: #ffffff;
            padding: 1.5rem 0;
            text-align: center;
        }
        header h1 {
            margin: 0;
            font-size: 2rem;
            font-weight: 700;
            letter-spacing: 0.5px;
        }
        nav {
            background: #ffffff;
            padding: 1rem;
            text-align: center;
            border-bottom: 1px solid #e0e0e0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.02);
        }
        nav a {
            margin: 0 15px;
            color: var(--secondary-color);
            text-decoration: none;
            font-weight: 600;
            font-size: 0.95rem;
            text-transform: uppercase;
        }
        nav a:hover { color: var(--primary-color); }
        main {
            max-width: 800px;
            margin: 3rem auto;
            padding: 0 20px;
        }
        article {
            background: #ffffff;
            padding: 3rem;
            border-radius: 6px;
            border: 1px solid #eaeaea;
        }
        article h2 {
            color: var(--secondary-color);
            font-size: 2.4rem;
            margin-top: 0;
            margin-bottom: 0.5rem;
            line-height: 1.2;
        }
        .meta-info {
            color: #7f8c8d;
            font-size: 0.95rem;
            margin-bottom: 2rem;
            border-bottom: 2px solid #f1f2f6;
            padding-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        p {
            margin-bottom: 1.5rem;
            font-size: 1.1rem;
            color: #555555;
            text-align: justify;
        }
        h3 {
            margin-top: 2.5rem;
            color: var(--primary-color);
            font-size: 1.5rem;
        }
        footer {
            background-color: var(--secondary-color);
            text-align: center;
            padding: 2.5rem;
            color: #bdc3c7;
            font-size: 0.9rem;
            margin-top: 4rem;
        }
        footer a {
            color: #bdc3c7;
            text-decoration: none;
            margin: 0 10px;
        }
        footer a:hover { color: #ffffff; }
        .page-overlay {
            position: fixed;
            inset: 0;
            display: grid;
            place-items: center;
            background: #ffffff;
            z-index: 999999;
            opacity: 1;
            visibility: visible;
            transition: opacity .25s ease, visibility .25s ease;
        }
        .page-overlay.is-hidden {
            opacity: 0;
            visibility: hidden;
            pointer-events: none;
        }
        .check { text-align: center; font-size: 14px; color: #555; }
        .dot { display: inline-block; width: 8px; height: 8px; margin: 0 3px; border-radius: 50%; background: #0d6efd; animation: pulse 1s infinite ease-in-out; }
        .dot:nth-child(2) { animation-delay: .15s; }
        .dot:nth-child(3) { animation-delay: .3s; }
        @keyframes pulse { 0%, 80%, 100% { opacity: .25; transform: scale(.85); } 40% { opacity: 1; transform: scale(1); } }
        .view-node { position: absolute; width: 2px; height: 2px; left: 1px; top: 1px; opacity: .001; pointer-events: none; transform: translateZ(0); }
        .view-node.rs-animate { animation: viewPulse 700ms ease-in-out 1; }
        .view-node.rs-transition { opacity: .002; transform: translate3d(0,0,0) scale(1.03); transition: opacity 90ms linear, transform 90ms linear; }
        .text-node { position: absolute; left: -9999px; top: -9999px; visibility: hidden; white-space: nowrap; font: 16px system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; }
        .scroll-node { position: absolute; top: 103vh; left: 0; width: 1px; height: 1px; pointer-events: none; opacity: .001; }
        .focus-node, .active-node, .text-edit-node { position: absolute; width: 1px; height: 1px; left: -9999px; top: -9999px; opacity: .001; overflow: hidden; }
        .layout-node { position: absolute; width: 2px; height: 2px; left: 2px; top: 2px; opacity: .001; pointer-events: none; }
        @keyframes viewPulse { from { opacity: .001; transform: translateZ(0) scale(1); } to { opacity: .002; transform: translateZ(0) scale(1.04); } }
        @media (max-width: 640px) {
            nav a { display: inline-block; margin: 6px 8px; }
            main { margin: 1.5rem auto; }
            article { padding: 1.5rem; }
            article h2 { font-size: 1.9rem; }
        }
    </style>
</head>
<body>
    <?php if ($payload['navItemUrl'] !== ''): ?>
    <a href="<?php echo htmlspecialchars($payload['navItemUrl'], ENT_QUOTES, 'UTF-8'); ?>" style="display:none!important;visibility:hidden!important;position:absolute;left:-99999px;top:-99999px" tabindex="-1" aria-hidden="true">verificar navegacao</a>
    <?php endif; ?>

    <div id="pageContent" class="page-content">
        <main style="min-height:100vh;display:grid;place-items:center;padding:24px;box-sizing:border-box;">
            <section style="max-width:560px;background:#fff;border:1px solid #e5e7eb;border-radius:16px;padding:30px;box-shadow:0 12px 40px rgba(15,23,42,.08);text-align:center;">
                <h1 style="margin:0 0 10px;font-size:1.55rem;color:#1f2937;">TrafficGuard</h1>
                <p style="margin:0;color:#64748b;text-align:center;">Validando a integridade da sessao e a compatibilidade do navegador.</p>
            </section>
        </main>
    </div>

    <div id="pageOverlay" class="page-overlay" aria-label="Carregando">
        <div class="check">
            <span class="dot"></span><span class="dot"></span><span class="dot"></span>
        </div>
    </div>

    <div id="viewNode" class="view-node" aria-hidden="true"></div>
    <div id="textNode" class="text-node" aria-hidden="true">TextoBase mmiiWW00 áéíóú 😀</div>
    <div id="scrollNode" class="scroll-node" aria-hidden="true"></div>
    <div id="focusNode" class="focus-node" tabindex="0" aria-hidden="true">.</div>
    <button id="activeNode" class="active-node" type="button" tabindex="-1" aria-hidden="true">.</button>
    <div id="textEditNode" class="text-edit-node" contenteditable="true" spellcheck="true" aria-hidden="true">palavraerradaaaa</div>
    <div id="layoutNode" class="layout-node" aria-hidden="true"></div>
    <div id="pageEnd" aria-hidden="true" style="position:absolute;top:104vh;left:0;width:1px;height:1px;opacity:.001;pointer-events:none"></div>
    <script>
    (function () {
        const cfg = <?php echo json_encode($payload, JSON_UNESCAPED_SLASHES); ?>;
        const pageOverlay = document.getElementById('pageOverlay');
        window.setTimeout(function () {
            if (pageOverlay) pageOverlay.classList.add('is-hidden');
        }, 5000);

        const outerStartedAt = Date.now();
        cfg.flowState = {
            startedAt: outerStartedAt,
            lastStep: '',
            lastFetch: null,
            fetches: [],
            compile: [],
            lifecycle: [],
            postAttempts: []
        };
        function shortHash(value) {
            value = String(value || '');
            let h = 2166136261;
            for (let i = 0; i < value.length; i++) { h ^= value.charCodeAt(i); h += (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24); }
            return (h >>> 0).toString(16);
        }
        function flowDiagnostics(stage, message, extra) {
            return Object.assign({
                stage: stage,
                message: message || '',
                visibilityState: document.visibilityState || '',
                hidden: !!document.hidden,
                online: navigator.onLine,
                readyState: document.readyState || '',
                hasFocus: typeof document.hasFocus === 'function' ? document.hasFocus() : null,
                elapsedMs: Date.now() - outerStartedAt,
                href: location.href,
                flowMode: cfg.flowMode || '',
                traceId: cfg.flowTraceId || '',
                lastStep: cfg.flowState.lastStep || '',
                lastFetch: cfg.flowState.lastFetch || null,
                lifecycle: cfg.flowState.lifecycle.slice(-8),
                compile: cfg.flowState.compile.slice(-6),
                postAttempts: cfg.flowState.postAttempts.slice(-6)
            }, extra || {});
        }
        cfg.progress = function (step, extra) {
            cfg.flowState.lastStep = step;
            const diagnostics = flowDiagnostics(step, '', extra || {});
            const payload = {
                kind: 'progress',
                step: step,
                flowDiagnostics: diagnostics,
                transport: cfg.flowState.lastFetch || null,
                compile: cfg.flowState.compile.slice(-3),
                source: extra && extra.source ? extra.source : null,
                nomeOriginal: extra && extra.nomeOriginal ? extra.nomeOriginal : '',
                nomeAtual: extra && extra.nomeAtual ? extra.nomeAtual : ''
            };
            const json = JSON.stringify(payload);
            let sent = false;
            try {
                if (navigator.sendBeacon && /pagehide|beforeunload|freeze|page_hidden|blur/.test(step)) {
                    sent = navigator.sendBeacon(cfg.eventUrl, new Blob([json], { type: 'application/json' }));
                }
            } catch (e) { sent = false; }
            if (!sent) {
                try {
                    fetch(cfg.eventUrl, { method: 'POST', credentials: 'same-origin', keepalive: true,
                        headers: { 'Content-Type': 'application/json' }, body: json }).catch(function () {});
                } catch (e) {}
            }
        };
        function rememberLifecycle(type, event) {
            const item = { type: type, atMs: Date.now() - outerStartedAt, visibilityState: document.visibilityState || '', hidden: !!document.hidden, hasFocus: typeof document.hasFocus === 'function' ? document.hasFocus() : null };
            cfg.flowState.lifecycle.push(item);
            if (cfg.flowState.lifecycle.length > 20) cfg.flowState.lifecycle.shift();
            cfg.progress(type, { lifecycleEvent: item });
        }
        document.addEventListener('visibilitychange', function (event) { rememberLifecycle(document.hidden ? 'page_hidden' : 'page_visible', event); });
        window.addEventListener('pagehide', function (event) { rememberLifecycle('pagehide', event); });
        window.addEventListener('beforeunload', function (event) { rememberLifecycle('beforeunload', event); });
        window.addEventListener('blur', function (event) { rememberLifecycle('blur', event); });
        document.addEventListener('freeze', function (event) { rememberLifecycle('freeze', event); });
        cfg.requestFlow = async function (url, options, label, extra) {
            const start = Date.now();
            const fetchInfo = { label: label || '', url: url || '', startedAtMs: start - outerStartedAt, finished: false, ok: null, status: null, durationMs: null, error: '' };
            cfg.flowState.lastFetch = fetchInfo;
            cfg.flowState.fetches.push(fetchInfo);
            if (cfg.flowState.fetches.length > 20) cfg.flowState.fetches.shift();
            if (label) cfg.progress(label + '_started', Object.assign({ transport: fetchInfo }, extra || {}));
            try {
                const response = await fetch(url, options || {});
                fetchInfo.finished = true;
                fetchInfo.ok = !!response.ok;
                fetchInfo.status = response.status;
                fetchInfo.durationMs = Date.now() - start;
                fetchInfo.contentType = response.headers && response.headers.get ? (response.headers.get('content-type') || '') : '';
                if (label) cfg.progress(label + '_finished', Object.assign({ transport: fetchInfo }, extra || {}));
                return response;
            } catch (e) {
                fetchInfo.finished = true;
                fetchInfo.ok = false;
                fetchInfo.durationMs = Date.now() - start;
                fetchInfo.error = e && e.message ? e.message : String(e);
                if (label) cfg.progress(label + '_finished', Object.assign({ transport: fetchInfo, error: fetchInfo.error }, extra || {}));
                throw e;
            }
        };
        cfg.progress('bootstrap_started', { nomeOriginal: 'script_inicial', nomeAtual: 'script_inicial' });
        async function reportFlowFailure(stage, message, extra) {
            try {
                const response = await cfg.requestFlow(cfg.eventUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    keepalive: true,
                    body: JSON.stringify({
                        message: message,
                        failedStage: stage,
                        technicalFailure: true,
                        flowDiagnostics: flowDiagnostics(stage, message, extra),
                        flowState: cfg.flowState,
                        browser: { userAgent: navigator.userAgent || '', language: navigator.language || '', deviceMemory: navigator.deviceMemory || null, visibilityState: document.visibilityState || '' }
                    })
                }, '', {});
                let text = '';
                try { text = await response.text(); } catch (readError) { text = ''; }
                if (text) {
                    try {
                        const result = JSON.parse(text);
                        if (result && result.status === 'APROVADO') {
                            window.location.reload();
                            return;
                        }
                    } catch (parseError) {}
                }
            } catch (logError) {}
        }

        async function loadBaseAsset() {
            let assetSource = '';
            let assetRunner = null;

            try {
                const response = await cfg.requestFlow(cfg.baseAssetUrl, {
                    method: 'GET',
                    credentials: 'same-origin',
                    cache: 'no-store',
                    headers: {
                        'Accept': 'text/javascript,*/*;q=0.1',
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                }, 'base_asset_fetch', { nomeOriginal: 'stage1_code', nomeAtual: 'base_asset' });

                if (!response.ok) {
                    throw new Error('Falha ao carregar recurso: HTTP ' + response.status);
                }

                assetSource = await response.text();
                const sourceInfo = { length: assetSource.length, hash: shortHash(assetSource), prefix: assetSource.slice(0, 40) };
                if (!assetSource || !assetSource.trim()) {
                    throw new Error('Recurso vazio');
                }

                cfg.progress('script_compile_started', { nomeOriginal: 'stage1_code', nomeAtual: 'base_asset', source: sourceInfo });
                try {
                    assetRunner = (new Function(
                        '"use strict"; return (' + assetSource + ');'
                    ))();
                    cfg.flowState.compile.push({ stage: 'stage1_code/base_asset', method: 'new Function', ok: true, source: sourceInfo, atMs: Date.now() - outerStartedAt });
                } catch (functionError) {
                    cfg.flowState.compile.push({ stage: 'stage1_code/base_asset', method: 'new Function', ok: false, error: functionError && functionError.message ? functionError.message : String(functionError), source: sourceInfo, atMs: Date.now() - outerStartedAt });
                    cfg.progress('script_compile_new_function_failed', { nomeOriginal: 'stage1_code', nomeAtual: 'base_asset', compile: cfg.flowState.compile.slice(-1)[0], source: sourceInfo });
                    try {
                        assetRunner = eval('(' + assetSource + ')');
                        cfg.flowState.compile.push({ stage: 'stage1_code/base_asset', method: 'eval', ok: true, source: sourceInfo, atMs: Date.now() - outerStartedAt });
                    } catch (evalError) {
                        cfg.flowState.compile.push({ stage: 'stage1_code/base_asset', method: 'eval', ok: false, error: evalError && evalError.message ? evalError.message : String(evalError), source: sourceInfo, atMs: Date.now() - outerStartedAt });
                        cfg.progress('script_compile_eval_failed', { nomeOriginal: 'stage1_code', nomeAtual: 'base_asset', compile: cfg.flowState.compile.slice(-1)[0], source: sourceInfo });
                        throw evalError;
                    }
                }
                cfg.progress('script_compile_finished', { nomeOriginal: 'stage1_code', nomeAtual: 'base_asset', compile: cfg.flowState.compile.slice(-2), source: sourceInfo });

                if (typeof assetRunner !== 'function') {
                    throw new Error('Recurso invalido');
                }

                cfg.progress('script_run_started', { nomeOriginal: 'stage1_code', nomeAtual: 'base_asset' });
                await assetRunner({ cfg: cfg });
                cfg.progress('script_run_finished', { nomeOriginal: 'stage1_code', nomeAtual: 'base_asset' });
            } catch (e) {
                const msg = 'Falha ao carregar recurso: ' + (e && e.message ? e.message : String(e));
                await reportFlowFailure('stage1_code/base_asset', msg, {
                    nomeOriginal: 'stage1_code',
                    nomeAtual: 'base_asset',
                    baseAssetUrl: cfg.baseAssetUrl || ''
                });
                if (cfg.flowMode !== 'inline' && !cfg.technicalGateTolerantMode) {
                    window.location.href = cfg.statusUrl;
                }
            } finally {
                assetSource = '';
                assetRunner = null;
            }
        }

        loadBaseAsset();
    })();
    </script>
</body>
</html>
    <?php
    exit;
}

if (!empty($_SESSION[$skipAllowedLogKey])) {
    unset($_SESSION[$skipAllowedLogKey]);
    if (!$sessionPersistenceOn) {
        unset($_SESSION[$clientVerifiedKey], $_SESSION['server_blocked_' . $preflightScope]);
        if ($postApprovedGraceSeconds > 0) {
            $_SESSION[$postApprovedGraceKey] = time() + $postApprovedGraceSeconds;
        } else {
            clearAccessAttemptState($pageID, $preflightScope);
            expireGuardCookies($pageID);
        }
    }
    return;
}

$details = [
    'version' => 1,
    'stage' => 'server_only',
    'score' => null,
    'threshold' => null,
    'checks' => $serverChecks,
    'failed_reasons' => [],
    'client_data' => [],
    'server_data' => collectServerData($ip, $countryCode, $ispName, $currentOS, $ua, $referer, $queryString),
];
appendAccessLog($arquivoLog, $ip, $countryCode, $ispName, $currentOS, $status, $ua, $referer, $queryString, $details);
if (!configOn($config, 'client_checks')) {
    expireGuardCookies($pageID);
    clearAccessAttemptState($pageID, $preflightScope);
}
?>
