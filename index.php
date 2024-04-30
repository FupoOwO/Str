<!DOCTYPE html>
<html>
<head>
    <title>Регистрация и авторизация</title>
</head>
<body>
    <?php
        session_start();

       
        // Подключение к базе данных
        $host = 'localhost';
        $db = 'your_database_name';
        $user = 'your_username';
        $password = 'your_password';

        $conn = new PDO("mysql:host=$host;dbname=$db;charset=utf8", $user, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Обработка регистрации
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['register'])) {
            $name = $_POST['name'];
            $email = $_POST['email'];
            $password = $_POST['password'];

            // Проверка, существует ли уже пользователь с такой электронной почтой
            $stmt = $conn->prepare('SELECT COUNT(*) FROM users WHERE email = :email');
            $stmt->bindParam(':email', $email);
            $stmt->execute();
            $userCount = $stmt->fetchColumn();

            if ($userCount > 0) {
                echo 'Пользователь с этим адресом электронной почты уже существует.';
            } else {
                // Хеширование пароля
                $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

                // Сохранение пользователя в базе данных
                $stmt = $conn->prepare('INSERT INTO users (name, email, password) VALUES (:name, :email, :password)');
                $stmt->bindParam(':name', $name);
                $stmt->bindParam(':email', $email);
                $stmt->bindParam(':password', $hashedPassword);
                $stmt->execute();

                echo 'Регистрация успешна. Теперь вы можете войти на сайт.';
            }
        }

        // Обработка авторизации
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
            $email = $_POST['email'];
            $password = $_POST['password'];

            // Поиск пользователя по электронной почте
            $stmt = $conn->prepare('SELECT * FROM users WHERE email = :email');
            $stmt->bindParam(':email', $email);
            $stmt->execute();
            $user = $stmt->fetch();

            if ($user && password_verify($password, $user['password'])) {
                // Успешная авторизация
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['user_name'] = $user['name'];
                header('Location: welcome.php');
                exit();
            } else {
                echo 'Неверные данные для входа.';
            }
        }

        // Обработка разлогинивания
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['logout'])) {
            session_unset();
            session_destroy();
            header('Location: login.php');
            exit();
        }
    ?>

    <!-- Форма регистрации -->
    <h2>Регистрация</h2>
    <form action="" method="POST">
        <input type="text" name="name" placeholder="Имя" required><br>
        <input type="email" name="email" placeholder="Электронная почта" required><br>
        <input type="password" name="password" placeholder="Пароль" required><br>
        <input type="submit" name="register" value="Зарегистрироваться">
    </form>

    <!-- Форма авторизации -->
    <h2>Авторизация</h2>
    <form action="" method="POST">
        <input type="email" name="email" placeholder="Электронная почта" required><br>
        <input type="password" name="password" placeholder="Пароль" required><br>
        <input type="submit" name="login" value="Войти">
    </form>

    <?php if (isset($_SESSION['user_id'])): ?>
        <!-- Приветственное сообщение и разлогинивание -->
        <h2>Добро пожаловать, <?php echo $_SESSION['user_name']; ?>!</h2>
               <form action="" method="POST">
            <input type="submit" name="logout" value="Выйти">
        </form>
    <?php endif; ?>

</body>
</html>
