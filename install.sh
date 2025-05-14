#!/bin/bash

echo "[*] Установка зависимостей..."

# Обновление пакетов и установка pip
sudo apt update
sudo apt install -y python3 python3-pip python3-venv

echo "[*] Инициализация виртуального окржения..."
mkdir venv/
python3 -m venv venv/

# Установка Python-зависимостей
echo "[*] Установка Python-зависимостей..."
venv/bin/pip3 install -r requirements.txt

echo "[*] Создание структуры каталогов..."
mkdir -p log detectors utils

echo "[!!!] Установка завершена. Для запуска введите следующую команду:"
echo "    sudo venv/bin/python3 main.py"
