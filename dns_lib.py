# -*- coding: utf-8 -*-
import socket
import binascii
import json
import datetime
import os

ADDRESS = "8.8.8.8"
PORT = 53


def get_hex_url(url):
    """ Возвращает байтовое представление секций URL """

    url_sections = url.split('.')
    if url_sections[-1] == '':
        del url_sections[-1]
    url_sections_in_hex = []
    for section in url_sections:
        new_section_in_bites = []
        for letter in section:
            new_section_in_bites.append(format(ord(letter), 'x'))
        url_sections_in_hex.append(new_section_in_bites)
    return url_sections_in_hex


def get_QNAME(url):
    """ Возвращает имя URL для секции QNAME вопроса """

    url_sections_in_hex = get_hex_url(url)
    QNAME = []
    for section in url_sections_in_hex:
        section_len_in_hex = format(len(section), 'x')
        if len(section_len_in_hex) == 1:
            QNAME.append('0' + section_len_in_hex)
        else:
            QNAME.append(section_len_in_hex)
        QNAME += section
    QNAME.append("00")
    return ''.join(QNAME)


def get_PTR(ip):
    """ Возвращает URL-адрес в формате PTR """

    reversed_ip = ip.split('.')
    reversed_ip.reverse()
    return '.'.join(reversed_ip) + '.in-addr.arpa.'


def get_question_HEAD():
    """ Возвращает байтовое представление заголовка запроса с вопросом """

    ID = "aaaa"
    parameters = "0100"  # RD=1, others=0
    QDCOUNT = "0001"
    ANCOUNT = "0000"
    NSCOUNT = "0000"
    ARCOUNT = "0000"
    return "".join([ID, parameters, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT])


def get_answer_HEAD():
    """ Возвращает байтовое представление заголовка запроса с ответом """

    ID = "aaaa"
    parameters = "8900"  # QR, Opcode, RD = 1
    QDCOUNT = "0000"
    ANCOUNT = "0001"
    NSCOUNT = "0000"
    ARCOUNT = "0000"
    return "".join([ID, parameters, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT])


def get_QUESTION(url):
    """ Возвращает байтовое представление вопроса запроса """

    QTYPE = "0001"
    QCLASS = "0001"
    return "".join([get_QNAME(url), QTYPE, QCLASS])


def get_ANSWER(ip):
    """ Возвращает байтовое представление ответа запроса """

    NAME = "c00c"
    TYPE = "0001"
    CLASS = "0001"
    TTL = "00001000"
    RDLENGTH = "0004"
    return "".join([NAME, TYPE, CLASS, TTL, RDLENGTH, get_RDDATA(ip)])


def get_RDDATA(ip):
    """ Возвращает байтовое представление IP-адреса """

    ip = ip.split(".")
    RDDATA = []
    for i in ip:
        RDDATA.append(format(int(i), "x"))
    return "".join(RDDATA)


def get_request(url, type):
    """ Формирует запрос к DNS серверу """

    if type == "i":
        return get_question_HEAD() + get_QUESTION(url)
    return get_answer_HEAD() + get_ANSWER(url)


def send_udp_message(url, address, port, type):
    """ Отправляет запрос на сервер """

    message = get_request(url, type)
    server_address = (address, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10)
    data = None
    try:
        sock.sendto(binascii.unhexlify(message), server_address)
        data, _ = sock.recvfrom(4096)
    except:
        return None
    finally:
        sock.close()
    if data is None:
        return None
    return binascii.hexlify(data).decode("utf-8")


def split_answer(answer):
    """ Возвращает байтовое представление ответа """

    answer_in_bites = [answer[i:i + 2] for i in range(0, len(answer), 2)]
    i = 12
    while answer_in_bites[i] != "00":
        url_len = int(answer_in_bites[i], 16)
        i += url_len + 1
    ANSWER_start_index = i + 2 + 2 + 1
    RDLENGTH = int(''.join(answer_in_bites[ANSWER_start_index + 10:ANSWER_start_index + 12]), 16)
    ANSWER = answer_in_bites[ANSWER_start_index:ANSWER_start_index + 12 + RDLENGTH]
    return ANSWER


def get_IP(ANSWER, url):
    """ Возвращает IP """

    RDLENGTH = int(''.join(ANSWER[10:12]), 16)
    RDATA_in_bites = ANSWER[12:12 + RDLENGTH]
    TYPE = int(''.join(ANSWER[2:4]), 16)
    TTL = int(''.join(ANSWER[6:10]), 16)
    death_time = datetime.datetime.now() + datetime.timedelta(seconds=TTL)
    if TYPE == 1:
        IP_list = []
        for i in RDATA_in_bites:
            IP_list.append(str(int(i, 16)))
        ip = ".".join(IP_list)
        cashing_new_data(url, ip, death_time)
        return ip
    elif TYPE == 5:
        new_url = get_url_from_bites(RDATA_in_bites)
        return get_ip_from_url(new_url)
    else:
        return "Этот тип записи не разобран!"


def get_url_from_bites(bites):
    """ Преобразует байты в URL """

    i = 0
    url = []
    while i < len(bites):
        section = []
        section_len = int(bites[i], 16)
        if i + section_len + 1 > len(bites):
            break
        for j in range(i + 1, i + 1 + section_len):
            section.append(chr(int(bites[j], 16)))
        url.append(''.join(section))
        i += section_len + 1
    return '.'.join(url)


def parse_answer(answer, url):
    """ Работает с ответом DNS сервера """

    ANSWER = split_answer(answer)
    return get_IP(ANSWER, url)


def parse_question(question):
    """ Работает с вопросом у ответа сервера """

    URL = []
    i = 12
    while question[i] != "00":
        section_len = int(question[i], 16)
        section = []
        for j in range(i + 1, i + section_len + 1):
            section.append(chr(int(question[j], 16)))
        URL.append("".join(section))
        i += section_len + 1
    return ".".join(URL)


def get_ip_from_url(url):
    """ Основная функция получения IP-адреса по URL """

    if ".multiply" in url:
        return multiply(url)
    ip = check_data_in_cash(url)
    if ip is not None:
        return f"(from cash) {ip}"
    answer = send_udp_message(url, ADDRESS, PORT, "i")
    ip = parse_answer(answer, url)
    return ip


def get_url_from_ip(ip):
    """ Основная функция получения URL-адреса по IP """

    url = check_data_in_cash(ip)
    if url is not None:
        return f"(from cash) {url}"
    question = send_udp_message(ip, ADDRESS, PORT, "u")
    if question is None:
        return "Что-то пошло не так!"
    url = parse_question(question)
    return url


def cashing_new_data(url, ip, death_time):
    """ Кэширует новые данные """

    new_cash_data = {url: [ip, death_time.strftime('%X %x')],
                     ip: [url, death_time.strftime('%X %x')]}
    with open("cash.json", "r") as read_file:
        old_cash_data = json.load(read_file)
    with open("cash.json", "w") as write_file:
        json.dump({**old_cash_data, **new_cash_data}, write_file)


def check_data_in_cash(url):
    """ Проверяет наличие данных в кэше """

    if not os.path.exists("cash.json"):
        with open("cash.json", "w") as write_file:
            json.dump({}, write_file)
            return None
    with open("cash.json", "r") as read_file:
        now = datetime.datetime.now()
        cash = json.load(read_file)
        if url in cash.keys():
            if now < datetime.datetime.strptime(cash[url][1], '%X %x'):
                return cash[url][0]
            else:
                del cash[cash[url][0]]
                del cash[url]
        return None


def multiply(url):
    """ Умножает числа по модулю 256 """

    url = url.split(".")
    if url[-1] == "":
        del url[-1]
    mult = 1
    for section in url[:url.index("multiply")]:
        mult = mult * int(section) % 256
    return f"127.0.0.{mult}"
