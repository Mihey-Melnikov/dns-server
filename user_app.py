# -*- coding: utf-8 -*-
import dns_lib


def run():
    """ Запускает работу приложения """

    print("Мини DNS-сервер\n")
    exit_app = False
    while not exit_app:
        key = input("\nВедите ключ, помощь: -h, --help: ").strip()
        exit_app = get_args(key)


def get_args(key):
    """ Разбирает аргументы """

    if key in ['-h', '--help']:
        print_helper()
        return False
    elif key in ['-i', '--get_ip']:
        get_ip_from_domain()
        return False
    elif key in ['-u', '--get_url']:
        get_url_from_ip()
        return False
    elif key in ['-e', '--exit']:
        print("Спасибо, что воспользовались нашим мини DNS-сервером!")
        input("Для выхода нажмите любую клавишу...")
        return True
    else:
        print(f"Ключ {key} не найден! Помощь: -h, --help")
        return False


def print_helper():
    """ Выводит помощь """

    with open("helper.txt", encoding="utf-8") as helper:
        print(helper.read())


def get_ip_from_domain():
    """ Выводит IP-адрес по URL """

    url = input("Введите URL-адрес: ")
    ip = dns_lib.get_ip_from_url(url)
    print(f"IP-адрес: {ip}")


def get_url_from_ip():
    """ Выводит URL по IP-адресу """

    ip = input("Введите IP-адрес: ")
    url = dns_lib.get_ip_from_url(dns_lib.get_PTR(ip))
    print(f"IP-адрес: {url}")
