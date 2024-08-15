<?php
// processar_consentimento.php

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

    // Insere os dados no banco de dados
    $sql = "INSERT INTO consentimentos (email, consentimento_comunicacoes, consentimento_cookies) VALUES (?, ?, ?)";

    $stmt = $conn->prepare($sql);
    $stmt->bind_param("sii", $email, $consentimento_comunicacoes, $consentimento_cookies);

    if ($stmt->execute()) {
        echo "Obrigado por dar o seu consentimento!";

        // Se o consentimento para cookies for dado, crie um cookie
        if ($consentimento_cookies) {
            setcookie("usuario_consentido", $email, time() + (86400 * 30), "/"); // Expira em 30 dias
        }
    } else {
        echo "Erro: " . $sql . "<br>" . $conn->error;
    }

    $stmt->close();
    $conn->close();
}
?>
