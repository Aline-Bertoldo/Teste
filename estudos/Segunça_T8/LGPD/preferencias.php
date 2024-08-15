<?php
// preferências.php

// Conexão com o banco de dados
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "seguro";
$port = 7306;

$conn = new mysqli($servername, $username, $password, $dbname, $port);

if ($conn->connect_error) {
    die("Falha na conexão: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = $_POST['email'];
    $consentimento_comunicacoes = isset($_POST['consentimento_comunicacoes']) ? 1 : 0;
    $consentimento_cookies = isset($_POST['consentimento_cookies']) ? 1 : 0;

    // Atualiza as preferências no banco de dados
    $sql = "UPDATE consentimentos SET consentimento_comunicacoes=?, consentimento_cookies=? WHERE email=?";

    $stmt = $conn->prepare($sql);
    $stmt->bind_param("iis", $consentimento_comunicacoes, $consentimento_cookies, $email);

    if ($stmt->execute()) {
        echo "Preferências atualizadas com sucesso!";

        // Atualiza o cookie se necessário
        if ($consentimento_cookies) {
            setcookie("usuario_consentido", $email, time() + (86400 * 30), "/"); // Expira em 30 dias
        } else {
            setcookie("usuario_consentido", "", time() - 3600, "/"); // Exclui o cookie
        }
    } else {
        echo "Erro ao atualizar preferências: " . $sql . "<br>" . $conn->error;
    }

    $stmt->close();
    $conn->close();
} else {
    $email = $_GET['email'];

    // Busca as preferências atuais do usuário
    $sql = "SELECT consentimento_comunicacoes, consentimento_cookies FROM consentimentos WHERE email=?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->bind_result($consentimento_comunicacoes, $consentimento_cookies);
    $stmt->fetch();
    $stmt->close();
    $conn->close();
}
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gerenciar Preferências de Consentimento</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
        }
        .consent-form {
            max-width: 500px;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 5px;
            background-color: #f9f9f9;
        }
        .consent-form label {
            display: block;
            margin-bottom: 10px;
        }
        .consent-form input[type="checkbox"] {
            margin-right: 10px;
        }
        .consent-form button {
            padding: 10px 20px;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        .consent-form button:hover {
            background-color: #45a049;
        }
    </style>
</head>
<body>

<div class="consent-form">
    <h2>Gerenciar Preferências de Consentimento</h2>
    <form action="preferencias.php" method="POST">
        <input type="hidden" name="email" value="<?php echo htmlspecialchars($email); ?>">
        <label>
            <input type="checkbox" name="consentimento_comunicacoes" <?php echo $consentimento_comunicacoes ? 'checked' : ''; ?>>
            Eu concordo em receber comunicações.
        </label>
        <label>
            <input type="checkbox" name="consentimento_cookies" <?php echo $consentimento_cookies ? 'checked' : ''; ?>>
            Eu concordo com o uso de cookies.
        </label>
        <button type="submit">Salvar Preferências</button>
    </form>
</div>

</body>
</html>
