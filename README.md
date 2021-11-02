# Мини DNS-сервер
###### Версия 1.0
###### Автор: Мельников Михей
###### Группа: ФТ-203
___

### Описание
Консольное приложение, выполняющее функции DNS-сервера:
- получение IP-адреса по URL-адресу
- получение URL-адреса по IP-адресу
- есть кэширование запросов с учетом времени жизни
___
### Требования
Python версии не ниже 3.6  
Кодировка UTF-8
___
### Состав проекта
- Файл запуска `main.py`
- Консольное приложение `user_app.py`
- Методы сервера `dns_lib.py`
- Справка `helper.txt`
- Описание `README.md`
- Кэш-файл `cash.json`
___
### Правила работы с приложением
- `-h, --help`: Вывод справки
- `-i, --get_ip`: Поиск IP-адреса по URL-адресу
- `-u, --get_url`: Поиск URL-адреса по IP-адресу
- `-e, --exit`: Выход