<?php
// Copy this file to config.php and fill in your MySQL/MariaDB credentials.
// config.php is git-ignored so real credentials never get committed.
//
// If MYSQL_HOST etc. are already set as real environment variables (e.g.
// picked up from the same .env used by mqtt_to_mysql.py, via your web
// server config or a shell export), those take priority and this file's
// values are only used as a fallback.

return [
    'host'     => '127.0.0.1',
    'port'     => 3306,
    'user'     => 'its_bridge',
    'password' => 'example',
    'database' => 'its_bridge',
];
