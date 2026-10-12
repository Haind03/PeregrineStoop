<?php
// Intentionally simple PHP practice target for PeregrineStoop.
// Run locally and point stoop at it. Authorized self-testing only.
//   php -S 127.0.0.1:8000 -t examples/targets/php
session_start(); // emits a PHPSESSID cookie
header('X-Powered-By: PHP/8.1 (demo)');

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

if ($path === '/robots.txt') {
    header('Content-Type: text/plain');
    echo "User-agent: *\nDisallow: /admin/\n";
    exit;
}
if ($path === '/go') {
    // demo open-redirect: reflects `next` into Location unchanged
    $next = isset($_GET['next']) ? $_GET['next'] : '/';
    header('Location: ' . $next);
    http_response_code(302);
    exit;
}

// demo reflected input: `q` echoed into HTML unencoded
$q = isset($_GET['q']) ? $_GET['q'] : '';
?>
<!doctype html>
<meta name="generator" content="DemoCMS 1.0">
<title>PHP demo target</title>
<body>
  <h1>PHP demo target</h1>
  <p>You searched for: <?php echo $q; ?></p>
  <a href="/admin/panel">admin</a>
  <script>fetch("/api/v1/users?id=1");</script>
</body>
