<?php
session_start();

if (!isset($_SESSION['userid'])) {
    header('Location: index.php');
    exit();
}

require_once 'db.php';

$userid = $_SESSION['userid'];

// Verifica se a autenticação em duas etapas já está habilitada
$sql_check_auth = "SELECT autenticacao_habilitada, codigo_autenticacao FROM usuarios WHERE id=?";
$stmt_check_auth = $mysqli->prepare($sql_check_auth);
$stmt_check_auth->bind_param("i", $userid);
$stmt_check_auth->execute();
$result_check_auth = $stmt_check_auth->get_result();

if ($result_check_auth->num_rows > 0) {
    $row = $result_check_auth->fetch_assoc();
    if (!$row['autenticacao_habilitada']) {
        // Se a autenticação em duas etapas não estiver habilitada, redireciona para o dashboard
        $_SESSION['message'] = "Autenticação em duas etapas não está habilitada.";
        header('Location: dashboard.php');
        exit();
    }

    // Se a autenticação em duas etapas estiver habilitada, gera um novo código de autenticação
    $codigo_autenticacao = $row['codigo_autenticacao'];
    if (!$codigo_autenticacao) {
        $codigo_autenticacao = rand(100000, 999999);
        $sql_update = "UPDATE usuarios SET codigo_autenticacao=? WHERE id=?";
        $stmt_update = $mysqli->prepare($sql_update);
        $stmt_update->bind_param("ii", $codigo_autenticacao, $userid);
        $stmt_update->execute();
        $stmt_update->close();
    }
} else {
    $_SESSION['error'] = "Erro ao verificar autenticação em duas etapas.";
    header('Location: dashboard.php');
    exit();
}

$stmt_check_auth->close();
$mysqli->close();
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Autenticação em Duas Etapas</title>
    <!-- CSS do modal (pode usar um framework como Bootstrap para facilitar) -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        /* Estilo para centralizar o modal */
        .modal-dialog-centered {
            display: flex;
            align-items: center;
            min-height: calc(100% - 1rem);
        }
    </style>
</head>
<body>
    <div class="container mt-5">
        <h2>Autenticação em Duas Etapas</h2>
        <?php if (isset($_SESSION['error'])): ?>
            <p style="color: red;"><?php echo $_SESSION['error']; ?></p>
            <?php unset($_SESSION['error']); ?>
        <?php endif; ?>
        <?php if (isset($_SESSION['message'])): ?>
            <p style="color: green;"><?php echo $_SESSION['message']; ?></p>
            <?php unset($_SESSION['message']); ?>
        <?php endif; ?>
        <p>Um código de autenticação foi enviado para você. Por favor, insira o código abaixo:</p>
        <form action="verificar_codigo.php" method="post">
            <label for="codigo">Código de Autenticação:</label><br>
            <input type="text" id="codigo" name="codigo" required><br><br>
            <input type="submit" value="Verificar Código">
            <!-- Botão para abrir o modal -->
            <button type="button" class="btn btn-primary ml-3" data-toggle="modal" data-target="#modalCodigo">
                Mostrar Código de Autenticação
            </button>
        </form>
    </div>

    <!-- Modal -->
    <div class="modal fade" id="modalCodigo" tabindex="-1" role="dialog" aria-labelledby="modalCodigoLabel" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="modalCodigoLabel">Código de Autenticação</h5>
                    <button type="button" class="close" data-dismiss="modal" aria-label="Fechar">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
                <div class="modal-body">
                    <p>O código de autenticação é: <strong><?php echo $codigo_autenticacao; ?></strong></p>
                    <p>Use este código para completar o processo de autenticação em duas etapas.</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">Fechar</button>
                </div>
            </div>
        </div>
    </div>

    <!-- JavaScript do Bootstrap (necessário para funcionamento do modal) -->
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.3/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>
