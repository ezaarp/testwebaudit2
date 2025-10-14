<?php
/**
 * vuln.php
 * Intentionally vulnerable: TAINTED SQL STRING (SQL Injection)
 * Use ONLY in local/lab environment.
 */

declare(strict_types=1);

// Simple SQLite DB path (will be created automatically)
$dbFile = __DIR__ . '/db.sqlite';

try {
    $pdo = new PDO('sqlite:' . $dbFile);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Create sample table if not exists
    $pdo->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        secret TEXT
    )");

    // Insert sample rows (if table empty)
    $rowCount = $pdo->query("SELECT COUNT(*) as c FROM users")->fetch(PDO::FETCH_ASSOC)['c'];
    if ((int)$rowCount === 0) {
        $pdo->exec("INSERT INTO users (username, secret) VALUES
            ('alice', 'alice-secret'),
            ('bob', 'bob-secret'),
            ('admin', 'top-secret')");
    }
} catch (Exception $e) {
    http_response_code(500);
    echo "DB error: " . htmlspecialchars($e->getMessage());
    exit;
}

// -------- Vulnerable endpoint --------
// GET /vuln.php?user=alice
// vulnerable: $user is used directly in SQL string (TAINTED)
$user = isset($_GET['user']) ? $_GET['user'] : '';

if ($user === '') {
    echo "<h3>Usage</h3>\n";
    echo "<p>Call <code>?user=... </code> to query user row.</p>\n";
    echo "<p>Example: <a href='?user=alice'>?user=alice</a></p>\n";
    exit;
}

// ======= VULNERABLE QUERY (TAINTED SQL STRING) =======
$sql = "SELECT id, username, secret FROM users WHERE username = '" . $user . "';";

try {
    // This is intentionally insecure: concatenation leads to SQL injection
    $stmt = $pdo->query($sql);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    header('Content-Type: text/plain; charset=utf-8');
    echo "Executed SQL:\n";
    echo $sql . "\n\n";
    echo "Result:\n";
    if (count($rows) === 0) {
        echo "No rows.\n";
    } else {
        foreach ($rows as $r) {
            echo "id={$r['id']}, username={$r['username']}, secret={$r['secret']}\n";
        }
    }
} catch (Exception $e) {
    http_response_code(500);
    echo "Query error: " . htmlspecialchars($e->getMessage());
}
