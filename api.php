<?php
// EcomFlow Pro V4 API
// Includes: 16 tables, AES-256-CBC encryption, auto-migration, permissions check
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-User-Email');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(200); exit(); }

// ── DB Config ──
define('DB_HOST', '127.0.0.1');
define('DB_NAME', 'bwtdfuugam');
define('DB_USER', 'bwtdfuugam');
define('DB_PASS', 'xQYyKv8avF');

// ── Encryption Key (固定金鑰；勿洩漏) ──
define('ENC_KEY', '52EC_Firm_2026_v4_' . 'Ac9$kLmQw8z!rTvB5x');
define('ADMIN_EMAIL', 'info@52ec.tw');

function getDB() {
    try {
        $pdo = new PDO(
            'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4',
            DB_USER, DB_PASS,
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
             PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]
        );
        return $pdo;
    } catch (PDOException $e) {
        http_response_code(500);
        echo json_encode(['error' => $e->getMessage()]);
        exit();
    }
}

function ok($data) { echo json_encode(['ok' => true, 'data' => $data], JSON_UNESCAPED_UNICODE); exit(); }
function err($msg, $code = 400) { http_response_code($code); echo json_encode(['ok' => false, 'error' => $msg], JSON_UNESCAPED_UNICODE); exit(); }
function body() { return json_decode(file_get_contents('php://input'), true) ?? []; }

// ── AES-256-CBC encryption ──
function encrypt_string($plaintext) {
    if ($plaintext === null || $plaintext === '') return '';
    $key = hash('sha256', ENC_KEY, true);
    $iv = openssl_random_pseudo_bytes(16);
    $ciphertext = openssl_encrypt($plaintext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $ciphertext);
}

function decrypt_string($encoded) {
    if (empty($encoded)) return '';
    try {
        $data = base64_decode($encoded);
        if (strlen($data) < 17) return '';
        $key = hash('sha256', ENC_KEY, true);
        $iv = substr($data, 0, 16);
        $ciphertext = substr($data, 16);
        $plain = openssl_decrypt($ciphertext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
        return $plain === false ? '' : $plain;
    } catch (Exception $e) {
        return '';
    }
}

// ── Permission System (V4.2) ──
function getUserByEmail($pdo, $email) {
    if (!$email) return null;
    try {
        $stmt = $pdo->prepare("SELECT * FROM members WHERE LOWER(email) = LOWER(?) LIMIT 1");
        $stmt->execute([$email]);
        $u = $stmt->fetch();
        if (!$u) return null;
        if (isset($u['permissions']) && is_string($u['permissions'])) {
            $u['permissions'] = json_decode($u['permissions'], true) ?: [];
        }
        return $u;
    } catch (Exception $e) { return null; }
}

function isAdminUser($user) {
    if (!$user) return false;
    return strtolower($user['email'] ?? '') === strtolower(ADMIN_EMAIL);
}

function userHasPerm($user, $category, $action) {
    if (!$user) return false;
    if (isAdminUser($user)) return true;
    if (($user['perm'] ?? '') === 'manager') return true;
    $p = $user['permissions'] ?? [];
    if (!is_array($p)) return false;
    return !empty($p[$category][$action]);
}

function tablePermMap($table) {
    $map = [
        'brands'               => ['clients', 'view', 'edit', 'delete'],
        'tasks'                => ['tasks', 'view', 'edit', 'delete'],
        'kols'                 => ['kols', 'view', 'edit', 'delete'],
        'kol_contacts'         => ['kols', 'view', 'edit', 'delete'],
        'kol_brand_relations'  => ['kols', 'view', 'edit', 'delete'],
        'group_buyers'         => ['group_buyers', 'view', 'edit', 'delete'],
        'group_campaigns'      => ['group_campaigns', 'view', 'edit', 'edit'],
        'commissions'          => ['commissions', 'view', 'edit', 'edit'],
        'brand_credentials'    => ['clients', 'view', 'edit', 'delete'],
        'brand_task_fields'    => ['tasks', 'view', 'fields', 'fields'],
        'members'              => ['members', 'view', 'manage', 'manage'],
        'cal_events'           => ['tasks', 'view', 'edit', 'delete'],
        'notifications'        => ['tasks', 'view', 'view', 'view'],
        'daily_revenue'        => ['group_campaigns', 'view', 'edit', 'edit'],
        'email_templates'      => ['tasks', 'view', 'edit', 'delete'],
        'brand_products'       => ['clients', 'view', 'edit', 'delete'],
        'invoices'             => ['commissions', 'view', 'edit', 'edit'],
        'task_templates'       => ['tasks', 'view', 'edit', 'delete'],
        'file_attachments'     => ['tasks', 'view', 'edit', 'delete'],
        'activity_log'         => ['members', 'view', 'view', 'view'],
    ];
    return $map[$table] ?? null;
}

function enforcePermission($pdo, $user, $table, $method) {
    // 初裝階段（members 表為空）放行
    try {
        $cnt = (int)$pdo->query("SELECT COUNT(*) FROM members")->fetchColumn();
        if ($cnt === 0) return;
    } catch (Exception $e) { return; }

    if (isAdminUser($user)) return;

    if (!$user) {
        // 未登入只允許 GET members（登入頁需要）
        if ($method === 'GET' && $table === 'members') return;
        err('未授權：請先登入', 401);
    }

    $map = tablePermMap($table);
    if (!$map) return;

    [$category, $readAct, $writeAct, $delAct] = $map;
    $needed = $readAct;
    if ($method === 'POST' || $method === 'PUT') $needed = $writeAct;
    if ($method === 'DELETE') $needed = $delAct;

    if (!userHasPerm($user, $category, $needed)) {
        err("無權限：{$category}.{$needed}", 403);
    }
}

// ── Auto-migrate: add missing columns ──
function ensureColumn($pdo, $table, $column, $definition) {
    try {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM information_schema.COLUMNS 
                               WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND COLUMN_NAME = ?");
        $stmt->execute([DB_NAME, $table, $column]);
        if ($stmt->fetchColumn() == 0) {
            $pdo->exec("ALTER TABLE `$table` ADD COLUMN `$column` $definition");
        }
    } catch (Exception $e) {}
}

function initTables($pdo) {
    // ── V3 tables ──
    $pdo->exec("CREATE TABLE IF NOT EXISTS members (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100), ename VARCHAR(100), role VARCHAR(100),
        dept VARCHAR(100), email VARCHAR(200), phone VARCHAR(50),
        perm VARCHAR(20), hours INT DEFAULT 160,
        join_date VARCHAR(20), color VARCHAR(200), skills TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS brands (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(200), short VARCHAR(100), cat VARCHAR(100),
        emoji VARCHAR(10), color VARCHAR(100), contact VARCHAR(100),
        email VARCHAR(200), phone VARCHAR(50), note TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS tasks (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(500), brand VARCHAR(100), type VARCHAR(100),
        owner VARCHAR(100), collab JSON, due VARCHAR(20),
        hours DECIMAL(5,1), priority VARCHAR(20), status VARCHAR(20),
        description TEXT, tags JSON, comments JSON,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS kols (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(200), handle VARCHAR(100), platform VARCHAR(50),
        fans INT, er DECIMAL(5,2), views INT,
        email VARCHAR(200), line VARCHAR(100), brand VARCHAR(100),
        mode VARCHAR(20), fixed DECIMAL(10,2), rate DECIMAL(5,2),
        status VARCHAR(20), tags VARCHAR(500), note TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS commissions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        kol VARCHAR(200), brand VARCHAR(100), activity VARCHAR(500),
        sales DECIMAL(12,2), br DECIMAL(5,2), kr DECIMAL(5,2),
        kf DECIMAL(10,2), due VARCHAR(20), status VARCHAR(20),
        paid_date VARCHAR(20), note TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS cal_events (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(500), date VARCHAR(20), type VARCHAR(50),
        brand VARCHAR(100), owner VARCHAR(100), note TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS notifications (
        id INT AUTO_INCREMENT PRIMARY KEY,
        msg TEXT, type VARCHAR(20), is_read TINYINT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // ── V3 & V4 auto-migrations ──
    ensureColumn($pdo, 'members', 'password_hash', 'VARCHAR(100) NULL');
    ensureColumn($pdo, 'members', 'permissions', 'JSON NULL');
    ensureColumn($pdo, 'members', 'avatar', 'VARCHAR(500) NULL');
    ensureColumn($pdo, 'members', 'active', 'TINYINT DEFAULT 1');
    ensureColumn($pdo, 'members', 'last_login', 'TIMESTAMP NULL');

    ensureColumn($pdo, 'brands', 'code', 'VARCHAR(30) NULL');
    ensureColumn($pdo, 'brands', 'owner', 'VARCHAR(100) NULL');
    ensureColumn($pdo, 'brands', 'plan', 'VARCHAR(20) NULL');
    ensureColumn($pdo, 'brands', 'fee', 'INT DEFAULT 0');
    ensureColumn($pdo, 'brands', 'status', 'VARCHAR(20) DEFAULT "active"');
    ensureColumn($pdo, 'brands', 'start_date', 'VARCHAR(20) NULL');
    ensureColumn($pdo, 'brands', 'end_date', 'VARCHAR(20) NULL');
    ensureColumn($pdo, 'brands', 'domains', 'JSON NULL');
    ensureColumn($pdo, 'brands', 'product', 'VARCHAR(200) NULL');
    ensureColumn($pdo, 'brands', 'channels', 'JSON NULL');
    ensureColumn($pdo, 'brands', 'platform_fee', 'TINYINT DEFAULT 0');
    ensureColumn($pdo, 'brands', 'window_am', 'VARCHAR(100) NULL');
    ensureColumn($pdo, 'brands', 'window_pm', 'VARCHAR(100) NULL');
    ensureColumn($pdo, 'brands', 'revenue_history', 'JSON NULL');
    ensureColumn($pdo, 'brands', 'custom_fields', 'JSON NULL');
    ensureColumn($pdo, 'brands', 'archived', 'TINYINT DEFAULT 0');

    ensureColumn($pdo, 'tasks', 'domain', 'VARCHAR(30) NULL');
    ensureColumn($pdo, 'tasks', 'kpi', 'VARCHAR(500) NULL');
    ensureColumn($pdo, 'tasks', 'custom_data', 'JSON NULL');
    ensureColumn($pdo, 'tasks', 'order_index', 'INT DEFAULT 0');
    ensureColumn($pdo, 'tasks', 'parent_id', 'INT NULL');
    ensureColumn($pdo, 'tasks', 'template_id', 'INT NULL');

    ensureColumn($pdo, 'kols', 'ig_id', 'VARCHAR(100) NULL');
    ensureColumn($pdo, 'kols', 'ig_url', 'VARCHAR(500) NULL');
    ensureColumn($pdo, 'kols', 'fb_url', 'VARCHAR(500) NULL');
    ensureColumn($pdo, 'kols', 'blog_url', 'VARCHAR(500) NULL');
    ensureColumn($pdo, 'kols', 'yt_url', 'VARCHAR(500) NULL');
    ensureColumn($pdo, 'kols', 'tiktok_url', 'VARCHAR(500) NULL');
    ensureColumn($pdo, 'kols', 'threads_url', 'VARCHAR(500) NULL');
    ensureColumn($pdo, 'kols', 'kol_type', 'VARCHAR(50) NULL');
    ensureColumn($pdo, 'kols', 'mail', 'VARCHAR(200) NULL');
    ensureColumn($pdo, 'kols', 'line_id', 'VARCHAR(100) NULL');
    ensureColumn($pdo, 'kols', 'recipient', 'VARCHAR(100) NULL');
    ensureColumn($pdo, 'kols', 'address', 'VARCHAR(500) NULL');
    ensureColumn($pdo, 'kols', 'phone', 'VARCHAR(50) NULL');
    ensureColumn($pdo, 'kols', 'source', 'VARCHAR(100) NULL');
    ensureColumn($pdo, 'kols', 'fans_fb', 'INT NULL');
    ensureColumn($pdo, 'kols', 'fans_ig', 'INT NULL');
    ensureColumn($pdo, 'kols', 'fans_updated', 'VARCHAR(20) NULL');

    // ── New V4 tables ──
    $pdo->exec("CREATE TABLE IF NOT EXISTS brand_credentials (
        id INT AUTO_INCREMENT PRIMARY KEY,
        brand_id INT NOT NULL,
        platform VARCHAR(50), label VARCHAR(100),
        username_enc TEXT, password_enc TEXT,
        url VARCHAR(500), note TEXT,
        created_by VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_brand (brand_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS email_templates (
        id INT AUTO_INCREMENT PRIMARY KEY,
        brand_id INT NULL,
        template_type VARCHAR(50),
        subject VARCHAR(500), content LONGTEXT,
        variables JSON, note VARCHAR(500),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_brand (brand_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS brand_task_fields (
        id INT AUTO_INCREMENT PRIMARY KEY,
        brand_id INT NOT NULL,
        field_key VARCHAR(50), field_name VARCHAR(100),
        field_type VARCHAR(20), field_options JSON,
        sort_order INT DEFAULT 0, required TINYINT DEFAULT 0,
        INDEX idx_brand (brand_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS kol_brand_relations (
        id INT AUTO_INCREMENT PRIMARY KEY,
        kol_id INT NOT NULL, brand_id INT NOT NULL,
        status VARCHAR(30), invite_date VARCHAR(20), reply_date VARCHAR(20),
        collab_method VARCHAR(100), willingness VARCHAR(50),
        note TEXT, assigned_to VARCHAR(100),
        UNIQUE KEY uniq_kol_brand (kol_id, brand_id),
        INDEX idx_kol (kol_id), INDEX idx_brand (brand_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS kol_contacts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        kol_id INT NOT NULL, brand_id INT NULL,
        contact_type VARCHAR(50), content TEXT,
        contact_date DATE, operator VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_kol (kol_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS group_buyers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        no INT, gb_type VARCHAR(50), nickname VARCHAR(200),
        ig_handle VARCHAR(200), fb_url VARCHAR(500), blog_url VARCHAR(500),
        other_contact VARCHAR(500), mail VARCHAR(500),
        invite_date DATE, reply VARCHAR(100),
        collab_method VARCHAR(500), items VARCHAR(500),
        recipient VARCHAR(100), address VARCHAR(500), phone VARCHAR(50),
        note TEXT, collab_brands VARCHAR(500), status VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS group_campaigns (
        id INT AUTO_INCREMENT PRIMARY KEY,
        no INT, create_date DATE,
        gb_id INT, gb_name VARCHAR(200),
        brand_id INT, brand_name VARCHAR(200),
        commission_rate DECIMAL(5,4),
        sent_sample TINYINT, progress VARCHAR(50),
        campaign_period VARCHAR(100), period_start DATE, period_end DATE,
        revenue DECIMAL(12,2), payout_to_gb DECIMAL(12,2),
        settled TINYINT, wired TINYINT, billed TINYINT,
        assigned_to VARCHAR(100), note TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_brand (brand_id), INDEX idx_gb (gb_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS brand_products (
        id INT AUTO_INCREMENT PRIMARY KEY,
        brand_id INT NOT NULL, category VARCHAR(100),
        product_name VARCHAR(300), sku VARCHAR(100),
        original_price DECIMAL(10,2), original_cost DECIMAL(10,2),
        group_price DECIMAL(10,2), commission_rate DECIMAL(5,4),
        shipping DECIMAL(10,2), product_url VARCHAR(500),
        note VARCHAR(500), sort_order INT DEFAULT 0,
        INDEX idx_brand (brand_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS invoices (
        id INT AUTO_INCREMENT PRIMARY KEY,
        invoice_no VARCHAR(50), invoice_type VARCHAR(50),
        brand_id INT, gb_id INT,
        period_start DATE, period_end DATE,
        amount DECIMAL(12,2), tax_amount DECIMAL(12,2), net_amount DECIMAL(12,2),
        status VARCHAR(50), issue_date DATE, paid_date DATE,
        note TEXT, items JSON, created_by VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS task_templates (
        id INT AUTO_INCREMENT PRIMARY KEY,
        brand_id INT NULL, template_name VARCHAR(200),
        domain VARCHAR(30), tasks JSON, created_by VARCHAR(100),
        INDEX idx_brand (brand_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS file_attachments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        entity_type VARCHAR(50), entity_id INT,
        filename VARCHAR(500), filepath VARCHAR(1000),
        filesize INT, mime_type VARCHAR(100),
        uploaded_by VARCHAR(100),
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_entity (entity_type, entity_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS activity_log (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_name VARCHAR(100), user_email VARCHAR(200),
        action VARCHAR(100), entity_type VARCHAR(50), entity_id INT,
        details JSON, ip VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_user (user_name), INDEX idx_created (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // ── V4.2: Daily Revenue ──
    $pdo->exec("CREATE TABLE IF NOT EXISTS daily_revenue (
        id INT AUTO_INCREMENT PRIMARY KEY,
        brand_id INT NOT NULL,
        brand_name VARCHAR(200),
        channel VARCHAR(50) DEFAULT 'all',
        revenue_date DATE NOT NULL,
        amount DECIMAL(14,2) DEFAULT 0,
        note VARCHAR(500),
        created_by VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_brand_channel_date (brand_id, channel, revenue_date),
        INDEX idx_date (revenue_date),
        INDEX idx_brand (brand_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
}

// ── Router ──
$path = trim($_GET['path'] ?? '', '/');
$method = $_SERVER['REQUEST_METHOD'];
$parts = explode('/', $path);
$table = $parts[0] ?? '';
$id = isset($parts[1]) ? (int)$parts[1] : null;

$validTables = [
    'members','brands','tasks','kols','commissions','cal_events','notifications',
    'brand_credentials','email_templates','brand_task_fields',
    'kol_brand_relations','kol_contacts','group_buyers','group_campaigns',
    'brand_products','invoices','task_templates','file_attachments','activity_log',
    'daily_revenue'
];

$pdo = getDB();
initTables($pdo);

// ── Current user (from X-User-Email header) ──
$currentUserEmail = $_SERVER['HTTP_X_USER_EMAIL'] ?? '';
$currentUser = getUserByEmail($pdo, $currentUserEmail);

if ($path === 'init') ok('V4.2 tables ready');

// ── /me : 回傳目前登入使用者 ──
if ($path === 'me' && $method === 'GET') {
    if (!$currentUser) err('未登入', 401);
    $u = $currentUser;
    unset($u['password_hash']);
    $u['is_admin'] = isAdminUser($currentUser);
    ok($u);
}

// Special endpoints
if ($path === 'decrypt_credential' && $method === 'POST') {
    if (!isAdminUser($currentUser) && !userHasPerm($currentUser, 'clients', 'credentials')) {
        err('無權限查看帳密', 403);
    }
    $data = body();
    $id = $data['id'] ?? 0;
    $userEmail = $_SERVER['HTTP_X_USER_EMAIL'] ?? '';
    $stmt = $pdo->prepare("SELECT * FROM brand_credentials WHERE id = ?");
    $stmt->execute([$id]);
    $row = $stmt->fetch();
    if (!$row) err('Not found', 404);
    $logStmt = $pdo->prepare("INSERT INTO activity_log (user_email, action, entity_type, entity_id, ip) VALUES (?,?,?,?,?)");
    $logStmt->execute([$userEmail, 'view_credential', 'brand_credentials', $id, $_SERVER['REMOTE_ADDR'] ?? '']);
    ok([
        'username' => decrypt_string($row['username_enc']),
        'password' => decrypt_string($row['password_enc']),
        'url' => $row['url'],
        'note' => $row['note']
    ]);
}

// ── /revenue_summary?days=30&brand_id=&channel= ──
if ($path === 'revenue_summary' && $method === 'GET') {
    if (!isAdminUser($currentUser)
        && !userHasPerm($currentUser, 'group_campaigns', 'view')
        && !userHasPerm($currentUser, 'finance', 'view_revenue')) {
        err('無權限查看業績', 403);
    }
    $days     = max(1, min(365, (int)($_GET['days'] ?? 30)));
    $brandId  = isset($_GET['brand_id']) && $_GET['brand_id'] !== '' ? (int)$_GET['brand_id'] : null;
    $channel  = $_GET['channel'] ?? '';
    $startDate = date('Y-m-d', strtotime("-{$days} days"));
    $today     = date('Y-m-d');

    // 1. daily_revenue
    $sql1 = "SELECT brand_id, brand_name, channel, revenue_date AS date, SUM(amount) AS amount
             FROM daily_revenue
             WHERE revenue_date >= ? AND revenue_date <= ?";
    $params = [$startDate, $today];
    if ($brandId !== null) { $sql1 .= " AND brand_id = ?"; $params[] = $brandId; }
    if ($channel !== '')   { $sql1 .= " AND channel = ?";  $params[] = $channel; }
    $sql1 .= " GROUP BY brand_id, channel, revenue_date ORDER BY revenue_date ASC";
    $stmt = $pdo->prepare($sql1);
    $stmt->execute($params);
    $daily = $stmt->fetchAll();

    // 2. group_campaigns
    $sql2 = "SELECT id, brand_id, brand_name, gb_name, revenue AS amount,
                    COALESCE(create_date, DATE(created_at)) AS date,
                    campaign_period, wired
             FROM group_campaigns
             WHERE COALESCE(create_date, DATE(created_at)) >= ?
               AND COALESCE(create_date, DATE(created_at)) <= ?";
    $params2 = [$startDate, $today];
    if ($brandId !== null) { $sql2 .= " AND brand_id = ?"; $params2[] = $brandId; }
    $sql2 .= " ORDER BY date ASC";
    $stmt2 = $pdo->prepare($sql2);
    $stmt2->execute($params2);
    $camps = $stmt2->fetchAll();

    // 3. by_date
    $byDate = [];
    for ($i = 0; $i <= $days; $i++) {
        $d = date('Y-m-d', strtotime("-" . ($days - $i) . " days"));
        $byDate[$d] = ['date' => $d, 'total' => 0, 'daily_revenue' => 0, 'campaign_revenue' => 0];
    }
    foreach ($daily as $r) {
        $d = $r['date'];
        if (!isset($byDate[$d])) $byDate[$d] = ['date' => $d, 'total' => 0, 'daily_revenue' => 0, 'campaign_revenue' => 0];
        $byDate[$d]['daily_revenue'] += (float)$r['amount'];
        $byDate[$d]['total']         += (float)$r['amount'];
    }
    if ($channel === '' || $channel === 'group_buy') {
        foreach ($camps as $c) {
            $d = $c['date'];
            if (!isset($byDate[$d])) $byDate[$d] = ['date' => $d, 'total' => 0, 'daily_revenue' => 0, 'campaign_revenue' => 0];
            $byDate[$d]['campaign_revenue'] += (float)$c['amount'];
            $byDate[$d]['total']            += (float)$c['amount'];
        }
    }
    ksort($byDate);

    // 4. by_brand
    $byBrand = [];
    foreach ($daily as $r) {
        $bid = $r['brand_id'];
        if (!isset($byBrand[$bid])) $byBrand[$bid] = ['brand_id' => (int)$bid, 'brand_name' => $r['brand_name'], 'total' => 0];
        $byBrand[$bid]['total'] += (float)$r['amount'];
    }
    foreach ($camps as $c) {
        $bid = $c['brand_id'] ?: 0;
        if (!isset($byBrand[$bid])) $byBrand[$bid] = ['brand_id' => (int)$bid, 'brand_name' => $c['brand_name'] ?? '', 'total' => 0];
        $byBrand[$bid]['total'] += (float)$c['amount'];
    }

    ok([
        'days'      => $days,
        'start'     => $startDate,
        'end'       => $today,
        'by_date'   => array_values($byDate),
        'by_brand'  => array_values($byBrand),
        'daily'     => $daily,
        'campaigns' => $camps,
    ]);
}

if (!in_array($table, $validTables)) err('Invalid table: ' . $table);

// ── 統一權限攔截（CRUD 前）──
enforcePermission($pdo, $currentUser, $table, $method);

// JSON fields per table
$jsonFields = [
    'tasks' => ['collab','tags','comments','custom_data'],
    'brands' => ['domains','channels','revenue_history','custom_fields'],
    'members' => ['permissions'],
    'email_templates' => ['variables'],
    'brand_task_fields' => ['field_options'],
    'task_templates' => ['tasks'],
    'invoices' => ['items'],
    'activity_log' => ['details']
];

function encodeJSON($table, $row) {
    global $jsonFields;
    if (!isset($jsonFields[$table])) return $row;
    foreach ($jsonFields[$table] as $f) {
        if (isset($row[$f]) && is_string($row[$f])) {
            $row[$f] = json_decode($row[$f], true);
        }
    }
    return $row;
}

function prepareRow($table, $data) {
    global $jsonFields;
    if (!isset($jsonFields[$table])) return $data;
    foreach ($jsonFields[$table] as $f) {
        if (isset($data[$f]) && (is_array($data[$f]) || is_object($data[$f]))) {
            $data[$f] = json_encode($data[$f], JSON_UNESCAPED_UNICODE);
        }
    }
    return $data;
}

// Encrypt credential fields on write
function processCredentials($table, $data, $isUpdate = false) {
    if ($table === 'brand_credentials') {
        // Accept plain 'username' and 'password' from client, encrypt to *_enc
        if (isset($data['username'])) {
            $data['username_enc'] = encrypt_string($data['username']);
            unset($data['username']);
        }
        if (isset($data['password'])) {
            $data['password_enc'] = encrypt_string($data['password']);
            unset($data['password']);
        }
    }
    return $data;
}

// Mask credentials on read (don't return encrypted blobs or passwords)
function maskCredentials($table, $row) {
    if ($table === 'brand_credentials') {
        $row['has_username'] = !empty($row['username_enc']);
        $row['has_password'] = !empty($row['password_enc']);
        unset($row['username_enc'], $row['password_enc']);
    }
    return $row;
}

function getValidColumns($pdo, $table) {
    static $cache = [];
    if (isset($cache[$table])) return $cache[$table];
    $stmt = $pdo->prepare("SELECT COLUMN_NAME FROM information_schema.COLUMNS 
                           WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?");
    $stmt->execute([DB_NAME, $table]);
    $cols = [];
    while ($row = $stmt->fetch()) $cols[] = $row['COLUMN_NAME'];
    $cache[$table] = $cols;
    return $cols;
}

function filterValidColumns($pdo, $table, $data) {
    $valid = getValidColumns($pdo, $table);
    $filtered = [];
    foreach ($data as $k => $v) {
        if (in_array($k, $valid)) $filtered[$k] = $v;
    }
    return $filtered;
}

// ── Batch operations (for mass import/export) ──
if ($path === 'batch_insert' && $method === 'POST') {
    $data = body();
    $tb = $data['table'] ?? '';
    $rows = $data['rows'] ?? [];
    if (!in_array($tb, $validTables)) err('Invalid table');
    enforcePermission($pdo, $currentUser, $tb, 'POST');
    if (empty($rows)) err('No rows');
    $success = 0; $failed = 0; $errors = [];
    foreach ($rows as $row) {
        try {
            $row = prepareRow($tb, $row);
            $row = processCredentials($tb, $row);
            unset($row['id'], $row['created_at']);
            $row = filterValidColumns($pdo, $tb, $row);
            if (empty($row)) continue;
            $cols = implode(',', array_map(fn($k)=>"`$k`", array_keys($row)));
            $phs = implode(',', array_fill(0, count($row), '?'));
            $stmt = $pdo->prepare("INSERT INTO `$tb` ($cols) VALUES ($phs)");
            $stmt->execute(array_values($row));
            $success++;
        } catch (Exception $e) {
            $failed++;
            if (count($errors) < 5) $errors[] = $e->getMessage();
        }
    }
    ok(['success' => $success, 'failed' => $failed, 'errors' => $errors]);
}

// GET all
if ($method === 'GET' && !$id) {
    $stmt = $pdo->query("SELECT * FROM `$table` ORDER BY id ASC");
    $rows = $stmt->fetchAll();
    foreach ($rows as &$row) {
        $row = encodeJSON($table, $row);
        $row = maskCredentials($table, $row);
        if ($table === 'notifications') $row['read'] = (bool)$row['is_read'];
    }
    ok($rows);
}

// GET one
if ($method === 'GET' && $id) {
    $stmt = $pdo->prepare("SELECT * FROM `$table` WHERE id = ?");
    $stmt->execute([$id]);
    $row = $stmt->fetch();
    if (!$row) err('Not found', 404);
    $row = encodeJSON($table, $row);
    $row = maskCredentials($table, $row);
    ok($row);
}

// POST (insert)
if ($method === 'POST') {
    $data = prepareRow($table, body());
    $data = processCredentials($table, $data);
    if (empty($data)) err('No data');
    if ($table === 'notifications' && isset($data['read'])) {
        $data['is_read'] = $data['read'] ? 1 : 0;
        unset($data['read']);
    }
    unset($data['id'], $data['created_at']);
    $data = filterValidColumns($pdo, $table, $data);
    if (empty($data)) err('No valid fields');
    try {
        $cols = implode(',', array_map(fn($k)=>"`$k`", array_keys($data)));
        $phs = implode(',', array_fill(0, count($data), '?'));
        $stmt = $pdo->prepare("INSERT INTO `$table` ($cols) VALUES ($phs)");
        $stmt->execute(array_values($data));
    } catch (Exception $e) { err('Insert failed: ' . $e->getMessage(), 500); }
    $newId = $pdo->lastInsertId();
    $stmt2 = $pdo->prepare("SELECT * FROM `$table` WHERE id = ?");
    $stmt2->execute([$newId]);
    $row = $stmt2->fetch();
    $row = encodeJSON($table, $row);
    $row = maskCredentials($table, $row);
    if ($table === 'notifications') $row['read'] = (bool)$row['is_read'];
    ok($row);
}

// PUT (update)
if ($method === 'PUT' && $id) {
    $data = prepareRow($table, body());
    $data = processCredentials($table, $data, true);
    if (empty($data)) err('No data');
    if ($table === 'notifications' && isset($data['read'])) {
        $data['is_read'] = $data['read'] ? 1 : 0;
        unset($data['read']);
    }
    unset($data['id'], $data['created_at']);
    $data = filterValidColumns($pdo, $table, $data);
    if (empty($data)) err('No valid fields to update');
    try {
        $sets = implode(',', array_map(fn($k)=>"`$k` = ?", array_keys($data)));
        $vals = array_values($data);
        $vals[] = $id;
        $stmt = $pdo->prepare("UPDATE `$table` SET $sets WHERE id = ?");
        $stmt->execute($vals);
    } catch (Exception $e) { err('Update failed: ' . $e->getMessage(), 500); }
    $stmt2 = $pdo->prepare("SELECT * FROM `$table` WHERE id = ?");
    $stmt2->execute([$id]);
    $row = $stmt2->fetch();
    $row = encodeJSON($table, $row);
    $row = maskCredentials($table, $row);
    if ($table === 'notifications') $row['read'] = (bool)$row['is_read'];
    ok($row);
}

// DELETE
if ($method === 'DELETE' && $id) {
    $stmt = $pdo->prepare("DELETE FROM `$table` WHERE id = ?");
    $stmt->execute([$id]);
    ok(['deleted' => $id]);
}

err('Bad request');
