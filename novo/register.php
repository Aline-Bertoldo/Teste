<?php
session_start();

require_once 'db.php';

// Gera o token CSRF se não existir
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Sanitiza e valida os dados do formulário
    $username = sanitize_input($mysqli, $_POST['username']);
    $email = sanitize_input($mysqli, $_POST['email']);
    $senha = sanitize_input($mysqli, $_POST['senha']);
    $confirm_senha = sanitize_input($mysqli, $_POST['confirm_senha']);
    $csrf_token = $_POST['csrf_token'];

    // Verifica o token CSRF
    if (!hash_equals($_SESSION['csrf_token'], $csrf_token)) {
        $_SESSION['error'] = "Token CSRF inválido.";
        header('Location: register.php');
        exit();
    }

    if ($senha !== $confirm_senha) {
        $_SESSION['error'] = "As senhas não coincidem. Por favor, tente novamente.";
        header('Location: register.php');
        exit();
    }

    $stmt = $mysqli->prepare("SELECT * FROM usuarios WHERE username=? OR email=?");
    $stmt->bind_param("ss", $username, $email);
    $stmt->execute();
    $result_check_user = $stmt->get_result();

    if ($result_check_user->num_rows > 0) {
        $_SESSION['error'] = "Usuário ou e-mail já registrado. Por favor, escolha outro.";
        header('Location: register.php');
        exit();
    }

    $senha_hash = password_hash($senha, PASSWORD_DEFAULT);

    $stmt = $mysqli->prepare("INSERT INTO usuarios (username, email, senha) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $username, $email, $senha_hash);

    if ($stmt->execute()) {
        $_SESSION['success'] = "Usuário registrado com sucesso!";

        if (isset($_POST['autenticacao_duas_etapas']) && $_POST['autenticacao_duas_etapas'] == 1) {
            $userid = $mysqli->insert_id;
            $codigo_autenticacao = rand(100000, 999999);

            $stmt = $mysqli->prepare("UPDATE usuarios SET autenticacao_habilitada=1, codigo_autenticacao=? WHERE id=?");
            $stmt->bind_param("ii", $codigo_autenticacao, $userid);
            $stmt->execute();

            $_SESSION['message'] = "Autenticação em duas etapas habilitada. Um código de autenticação foi enviado para você.";
            header('Location: autenticacao.php');
            exit();
        } else {
            header('Location: login.php');
            exit();
        }
    } else {
        $_SESSION['error'] = "Erro ao registrar o usuário: " . $stmt->error;
    }
}

$mysqli->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registro</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/bootstrap.min.css" integrity="sha384-Zenh87qX5JnK2Jl0vWa8Ck2rdkQ2Bzep5IDxbcnCeuOxjzrPF/et3URy9Bv1WTRi" crossorigin="anonymous">
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <?php
        if (isset($_POST["submit"])) {
           $userName = $_POST["username"];
           $email = $_POST["email"];
           $senha = $_POST["senha"];
           $confirm_senha = $_POST["confirm_senha"];
           
           $passwordHash = password_hash($password, PASSWORD_DEFAULT);

           $errors = array();
           
           if (empty($userName) OR empty($email) OR empty($senha) OR empty($confirm_senha)) {
            array_push($errors,"Todos os campos são obrigatórios");
           }
           if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            array_push($errors, "O e-mail não é válido");
           }
           if (strlen($senha)<8) {
            array_push($errors,"A senha deve ter pelo menos 8 caracteres");
           }
           if ($senha!==$confirm_senha) {
            array_push($errors,"A senha não corresponde");
           }
           require_once "database.php";
           $sql = "SELECT * FROM users WHERE email = '$email'";
           $result = mysqli_query($conn, $sql);
           $rowCount = mysqli_num_rows($result);
           if ($rowCount>0) {
            array_push($errors,"O e-mail já existe!");
           }
           if (count($errors)>0) {
            foreach ($errors as  $error) {
                echo "<div class='alert alert-danger'>$error</div>";
            }
           }else{
            
            $sql = "INSERT INTO users (user_name, email, password) VALUES ( ?, ?, ? )";
            $stmt = mysqli_stmt_init($conn);
            $prepareStmt = mysqli_stmt_prepare($stmt,$sql);
            if ($prepareStmt) {
                mysqli_stmt_bind_param($stmt,"sss",$userName, $email, $passwordHash);
                mysqli_stmt_execute($stmt);
                echo "<div class='alert alert-success'>You are registered successfully.</div>";
            }else{
                die("Something went wrong");
            }
           }
          

        }
        ?>
        <script>
        function verificarSenha() {
            var senha = document.getElementById('senha').value;
            var confirmSenha = document.getElementById('confirm_senha').value;
            var mensagem = document.getElementById('mensagem-senha');
            var forte = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

            if (senha !== confirmSenha) {
                mensagem.className = 'red';
                mensagem.textContent = 'As senhas não coincidem.';
                return false;
            }

            if (forte.test(senha)) {
                mensagem.className = 'green';
                mensagem.textContent = 'Senha forte.';
                return true;
            } else {
                mensagem.className = 'red';
                mensagem.textContent = 'A senha deve ter pelo menos 8 caracteres, incluindo letras maiúsculas, minúsculas, números e caracteres especiais.';
                return false;
            }
        }
    </script>
    <body>
    <div class="register-container">
        <h2>Registro de Usuário</h2>
        <p>
        <?php if (isset($_SESSION['error'])): ?>
            <p style="color: red;"><?php echo $_SESSION['error']; ?></p>
            <?php unset($_SESSION['error']); ?>
        <?php endif; ?>
        <?php if (isset($_SESSION['success'])): ?>
            <p style="color: green;"><?php echo $_SESSION['success']; ?></p>
            <?php unset($_SESSION['success']); ?>
        <?php endif; ?>
        <form action="register.php" method="post">
            <div class="form-group">
                <input type="text" class="form-control" name="Nome" placeholder="Nome:">
            </div>
            <div class="form-group">
                <input type="emamil" class="form-control" name="Email" placeholder="Email:">
            </div>
            <div class="form-group">
                <input type="password" class="form-control" name="Senha" placeholder="Senha:">
            </div>
            <div class="form-group">
                <input type="password" class="form-control" name="Confirme Senha" placeholder="Confirme Senha:">
            </div>
            <div class="form-btn">
                <input type="submit" class="btn btn-primary" value="Registrar" name="submit">
            </div>
            <div>
                <br></br>
                <input type="checkbox" name="autenticacao_duas_etapas" value="1">Habilitar Autenticação em Duas Etapas
            </div>
        </form>
        <div>
            <p>
        <div>Usuário já registrado faça <a href="login.php">Login Aqui</a></div>
      </div>
    </div>
</body>
</html>

