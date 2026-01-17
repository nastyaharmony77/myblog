# Быстрый скан текущей директории
./scanner.sh

# Скан конкретного пути
./scanner.sh /home/user/public_html

# Глубокий скан (+ недавно изменённые файлы, длинные base64)
./_scanner.sh /home/user/public_html --deep


curl -L  https://raw.githubusercontent.com/nastyaharmony77/myblog/refs/heads/main/scanner.sh | sh
