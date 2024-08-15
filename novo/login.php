<?php
session_start();
require_once 'db.php';

// Gera o token CSRF se não existir
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Sanitiza e valida os dados do formulário
    $nome = sanitize_input($mysqli, $_POST['nome']);
    $senha = sanitize_input($mysqli, $_POST['senha']);
    $csrf_token = $_POST['csrf_token'];

    // Verifica o token CSRF
    if (!hash_equals($_SESSION['csrf_token'], $csrf_token)) {
        $_SESSION['error'] = "Token CSRF inválido.";
        header('Location: login.php');
        exit();
    }

    // Prepara a query usando prepared statements
    $stmt = $mysqli->prepare("SELECT id, senha, autenticacao_habilitada FROM usuarios WHERE username=?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows == 1) {
        $user = $result->fetch_assoc();

        if (password_verify($password, $user['senha'])) {
            $_SESSION['userid'] = $user['id'];
            $_SESSION['username'] = $username;

            // Regenera o token CSRF após login bem-sucedido
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

            if ($user['autenticacao_habilitada']) {
                header('Location: autenticacao.php');
            } else {
                header('Location: dashboard.php');
            }
            exit();
        } else {
            $_SESSION['error'] = "Credenciais incorretas. Por favor, tente novamente.";
        }
    } else {
        $_SESSION['error'] = "Usuário não encontrado.";
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
    <title>Login Form</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/bootstrap.min.css" integrity="sha384-Zenh87qX5JnK2Jl0vWa8Ck2rdkQ2Bzep5IDxbcnCeuOxjzrPF/et3URy9Bv1WTRi" crossorigin="anonymous">
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <?php
        if (isset($_POST["login"])) {
           $email = $_POST["email"];
           $password = $_POST["senha"];
            require_once "db.php";
            $sql = "SELECT * FROM users WHERE email = '$email'";
            $result = mysqli_query($conn, $sql);
            $user = mysqli_fetch_array($result, MYSQLI_ASSOC);
            if ($user) {
                if (password_verify($password, $user["senha"])) {
                    session_start();
                    $_SESSION["user"] = "yes";
                    header("Location: index.php");
                    die();
                }else{
                    echo "<div class='alert alert-danger'>Password does not match</div>";
                }
            }else{
                echo "<div class='alert alert-danger'>Email does not match</div>";
            }
        }
        ?>
        <div class="register-container">
        <h2>Login</h2>
        <p>
        <?php if (isset($_SESSION['error'])): ?>
            <p style="color: red;"><?php echo $_SESSION['error']; ?></p>
            <?php unset($_SESSION['error']); ?>
        <?php endif; ?>
        <?php if (isset($_SESSION['success'])): ?>
            <p style="color: green;"><?php echo $_SESSION['success']; ?></p>
            <?php unset($_SESSION['success']); ?>
        <?php endif; ?>
        <form action="login.php" method="post">
        <div class="form-group">
                <input type="text" class="form-control" name="Nome" placeholder="Nome:">
            </div>
        <div class="form-group">
            <input type="password" placeholder="Enter Senha:" name="Senha" class="form-control">
        </div>
        <div class="form-btn">
            <input type="submit" value="Login" name="login" class="btn btn-primary">
        <div class="form-btn">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
        </div>
      </form>
      <p>
     <div>Usuário não registrado <a href="register.php">Register</a></div>
    </div>
</body>
</html>