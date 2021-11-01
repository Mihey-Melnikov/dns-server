# -*- coding: utf-8 -*-
import socket
import binascii


ADDRESS = "8.8.8.8"
PORT = 53


def get_hex(url):
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

    url_sections_in_hex = get_hex(url)
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


def get_HEAD():
    """ Возвращает байтовое представление заголовка запроса """

    ID = "aaaa"
    parameters = "0100"  # RD=1, others=0
    QDCOUNT = "0001"
    ANCOUNT = "0000"
    NSCOUNT = "0000"
    ARCOUNT = "0000"
    return "".join([ID, parameters, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT])


def get_QUESTION(url):
    """ Возвращает байтовое представление вопроса запроса """

    QTYPE = "0001"
    QCLASS = "0001"
    return "".join([get_QNAME(url), QTYPE, QCLASS])


def get_request(url):
    """ Формирует запрос к DNS серверу """

    return get_HEAD() + get_QUESTION(url)


def send_udp_message(url, address, port):
    """ Отправляет запрос на сервер """

    message = get_request(url)
    server_address = (address, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(binascii.unhexlify(message), server_address)
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
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


def get_IP(ANSWER):
    """ Возвращает IP """

    RDLENGTH = int(''.join(ANSWER[10:12]), 16)
    RDATA_in_bites = ANSWER[12:12 + RDLENGTH]
    TYPE = int(''.join(ANSWER[2:4]), 16)
    if TYPE == 1:
        IP_list = []
        for i in RDATA_in_bites:
            IP_list.append(str(int(i, 16)))
        return ".".join(IP_list)
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


def parse_answer(answer):
    """ Работает с ответом DNS сервера """

    ANSWER = split_answer(answer)
    return get_IP(ANSWER)


def get_ip_from_url(url):
    """ Основная функция получения IP-адреса по URL """

    answer = send_udp_message(url, ADDRESS, PORT)
    ip = parse_answer(answer)
    return ip
