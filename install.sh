#!/bin/bash

echo "[*] Установка зависимостей..."

# Обновление пакетов и установка pip
sudo apt update
sudo apt install -y python3 python3-pip

# Установка Python-зависимостей
pip3 install -r requirements.txt

echo "[*] Создание структуры каталогов..."
mkdir -p log detectors utils

echo "[*] Установка завершена. Запуск:"
echo "    sudo python3 main.py"
