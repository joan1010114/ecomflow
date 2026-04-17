<?php
// EcomFlow Pro V3 API
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(200); exit(); }

// ── DB Config ──
define('DB_HOST', '127.0.0.1');
define('DB_NAME', 'bwtdfuugam');
define('DB_USER', 'bwtdfuugam');
define('DB_PASS', 'xQYyKv8avF');

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

function ok($data) { echo json_encode(['ok' => true, 'data' => $data]); exit(); }
function err($msg, $code = 400) { http_response_code($code); echo json_encode(['ok' => false, 'error' => $msg]); exit(); }
function body() { return json_decode(file_get_contents('php://input'), true) ?? []; }

// ── Auto-migrate: add missing columns ──
function ensureColumn($pdo, $table, $column, $definition) {
    try {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM information_schema.COLUMNS 
                               WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND COLUMN_NAME = ?");
        $stmt->execute([DB_NAME, $table, $column]);
        if ($stmt->fetchColumn() == 0) {
            $pdo->exec("ALTER TABLE `$table` ADD COLUMN `$column` $definition");
        }
    } catch (Exception $e) {
        // Silently ignore
    }
}

function initTables($pdo) {
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

    // ── V3 auto-migrations ──
    ensureColumn($pdo, 'members', 'password_hash', 'VARCHAR(100) NULL');

    ensureColumn($pdo, 'brands', 'code', 'VARCHAR(30) NULL');
    ensureColumn($pdo, 'brands', 'owner', 'VARCHAR(100) NULL');
    ensureColumn($pdo, 'brands', 'plan', 'VARCHAR(20) NULL');
    ensureColumn($pdo, 'brands', 'fee', 'INT DEFAULT 0');
    ensureColumn($pdo, 'brands', 'status', 'VARCHAR(20) DEFAULT "active"');
    ensureColumn($pdo, 'brands', 'start_date', 'VARCHAR(20) NULL');
    ensureColumn($pdo, 'brands', 'end_date', 'VARCHAR(20) NULL');
    ensureColumn($pdo, 'brands', 'domains', 'JSON NULL');

    ensureColumn($pdo, 'tasks', 'domain', 'VARCHAR(30) NULL');
    ensureColumn($pdo, 'tasks', 'kpi', 'VARCHAR(500) NULL');
}

$path = trim($_GET['path'] ?? '', '/');
$method = $_SERVER['REQUEST_METHOD'];
$parts = explode('/', $path);
$table = $parts[0] ?? '';
$id = isset($parts[1]) ? (int)$parts[1] : null;

$validTables = ['members','brands','tasks','kols','commissions','cal_events','notifications'];

$pdo = getDB();
initTables($pdo);

if ($path === 'init') ok('Tables ready with V3 schema');

if (!in_array($table, $validTables)) err('Invalid table: ' . $table);

$jsonFields = [
    'tasks' => ['collab','tags','comments'],
    'brands' => ['domains']
];

function encodeJSON($table, $row) {
    global $jsonFields;
    if (!isset($jsonFields[$table])) return $row;
    foreach ($jsonFields[$table] as $f) {
        if (isset($row[$f]) && is_string($row[$f])) {
            $row[$f] = json_decode($row[$f], true) ?? [];
        }
    }
    return $row;
}

function prepareRow($table, $data) {
    global $jsonFields;
    if (!isset($jsonFields[$table])) return $data;
    foreach ($jsonFields[$table] as $f) {
        if (isset($data[$f]) && is_array($data[$f])) {
            $data[$f] = json_encode($data[$f], JSON_UNESCAPED_UNICODE);
        }
    }
    return $data;
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

if ($method === 'GET' && !$id) {
    $stmt = $pdo->query("SELECT * FROM `$table` ORDER BY id ASC");
    $rows = $stmt->fetchAll();
    foreach ($rows as &$row) {
        $row = encodeJSON($table, $row);
        if ($table === 'notifications') $row['read'] = (bool)$row['is_read'];
    }
    ok($rows);
}

if ($method === 'GET' && $id) {
    $stmt = $pdo->prepare("SELECT * FROM `$table` WHERE id = ?");
    $stmt->execute([$id]);
    $row = $stmt->fetch();
    if (!$row) err('Not found', 404);
    ok(encodeJSON($table, $row));
}

if ($method === 'POST') {
    $data = prepareRow($table, body());
    if (empty($data)) err('No data');
    if ($table === 'notifications' && isset($data['read'])) {
        $data['is_read'] = $data['read'] ? 1 : 0;
        unset($data['read']);
    }
    unset($data['id'], $data['created_at']);
    $data = filterValidColumns($pdo, $table, $data);
    if (empty($data)) err('No valid fields');
    try {
        $cols = implode(',', array_map(function($k){ return "`$k`"; }, array_keys($data)));
        $phs = implode(',', array_fill(0, count($data), '?'));
        $stmt = $pdo->prepare("INSERT INTO `$table` ($cols) VALUES ($phs)");
        $stmt->execute(array_values($data));
    } catch (Exception $e) {
        err('Insert failed: ' . $e->getMessage(), 500);
    }
    $newId = $pdo->lastInsertId();
    $stmt2 = $pdo->prepare("SELECT * FROM `$table` WHERE id = ?");
    $stmt2->execute([$newId]);
    $row = $stmt2->fetch();
    $row = encodeJSON($table, $row);
    if ($table === 'notifications') $row['read'] = (bool)$row['is_read'];
    ok($row);
}

if ($method === 'PUT' && $id) {
    $data = prepareRow($table, body());
    if (empty($data)) err('No data');
    if ($table === 'notifications' && isset($data['read'])) {
        $data['is_read'] = $data['read'] ? 1 : 0;
        unset($data['read']);
    }
    unset($data['id'], $data['created_at']);
    $data = filterValidColumns($pdo, $table, $data);
    if (empty($data)) err('No valid fields to update');
    try {
        $sets = implode(',', array_map(function($k){ return "`$k` = ?"; }, array_keys($data)));
        $vals = array_values($data);
        $vals[] = $id;
        $stmt = $pdo->prepare("UPDATE `$table` SET $sets WHERE id = ?");
        $stmt->execute($vals);
    } catch (Exception $e) {
        err('Update failed: ' . $e->getMessage(), 500);
    }
    $stmt2 = $pdo->prepare("SELECT * FROM `$table` WHERE id = ?");
    $stmt2->execute([$id]);
    $row = $stmt2->fetch();
    $row = encodeJSON($table, $row);
    if ($table === 'notifications') $row['read'] = (bool)$row['is_read'];
    ok($row);
}

if ($method === 'DELETE' && $id) {
    $stmt = $pdo->prepare("DELETE FROM `$table` WHERE id = ?");
    $stmt->execute([$id]);
    ok(['deleted' => $id]);
}

err('Bad request');
