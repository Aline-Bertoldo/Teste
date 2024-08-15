<?php
session_start();

// Verificar se o usuário está autenticado
if (!isset($_SESSION['username'])) {
    header("Location: login.php");
    exit();
}

// Verificar CSRF token se o método for POST
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("Ação não autorizada.");
    }
}

// Incluir o arquivo de conexão com o banco de dados
require_once 'db.php';
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Dashboard</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f0f0f0;
            text-align: center;
            padding-top: 50px;
        }

        .dashboard-container {
            max-width: 600px;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }

        .dashboard-container h2 {
            margin-bottom: 20px;
        }

        .dashboard-container a {
            display: inline-block;
            padding: 10px 20px;
            margin: 10px;
            background-color: #4CAF50;
            color: white;
            text-decoration: none;
            border-radius: 3px;
            font-size: 16px;
        }

        .dashboard-container a:hover {
            background-color: #45a049;
        }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <h2>Dashboard</h2>
        <p>Bem-vindo ao dashboard, <?php echo $_SESSION['username']; ?>!</p>
        <a href="criar_backup.php">Criar Backup</a><br><br>
        <a href="logout.php">Logout</a>
    </div>
</body>
</html>