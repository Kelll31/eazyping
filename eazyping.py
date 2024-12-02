import ipaddress
import subprocess
import concurrent.futures
import socket
import argparse
from tqdm import tqdm

def ping_host(ip, timeout):
    try:
        output = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), str(ip)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return output.returncode == 0
    except Exception as e:
        tqdm.write(f"Ошибка при пинге {ip}: {e}")
        return False

def resolve_domain_to_cidr(domain):
    try:
        ip = socket.gethostbyname(domain)
        return f"{ip}/32"
    except socket.gaierror as e:
        tqdm.write(f"Не удалось разрешить домен {domain}: {e}")
        return None

def check_port(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError):
        return False

def parse_ports(port_string):
    ports = set()
    for part in port_string.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return ports

def traceroute(ip):
    try:
        output = subprocess.run(
            ["traceroute", str(ip)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return output.stdout.decode('utf-8')
    except Exception as e:
        tqdm.write(f"Ошибка при выполнении traceroute для {ip}: {e}")
        return None

def ping_cidr(cidr, show_all, timeout, max_threads, check_ports, traceroute_enabled):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_ip = {executor.submit(ping_host, ip, timeout): ip for ip in network.hosts()}
            with tqdm(total=len(future_to_ip), desc="Scanning", unit="ip", position=0, leave=False) as pbar:
                for future in concurrent.futures.as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    is_alive = future.result()
                    results[str(ip)] = {"alive": is_alive}
                    if check_ports and is_alive:
                        results[str(ip)]["open_ports"] = []
                        for port in check_ports:
                            if check_port(ip, port, timeout):
                                results[str(ip)]["open_ports"].append(port)
                    if show_all or is_alive:
                        status = "работает" if is_alive else "не работает"
                        ports_info = f", открытые порты: {results[str(ip)].get('open_ports', [])}" if is_alive else ""
                        tqdm.write(f"{ip} {status}{ports_info}")

                    if is_alive and traceroute_enabled:
                        traceroute_output = traceroute(ip)
                        if traceroute_output:
                            tqdm.write(f"Traceroute для {ip}:\n{traceroute_output}")
                            results[str(ip)]["traceroute"] = traceroute_output

                    pbar.update(1)

        return results
    except ValueError as e:
        tqdm.write(f"Неверный формат CIDR: {e}")
        return {}

def save_report(results, filename, format):
    try:
        with open(filename, 'w') as f:
            sorted_ips = sorted((ip for ip, info in results.items() if info['alive']), key=lambda ip: ipaddress.ip_address(ip))
            for ip in sorted_ips:
                info = results[ip]
                f.write(f"{ip}\n")
                if 'open_ports' in info:
                    f.write(f"  Открытые порты: {', '.join(map(str, info['open_ports']))}\n")
                if 'traceroute' in info:
                    f.write(f"  Traceroute:\n{info['traceroute']}\n")
        tqdm.write(f"Отчет сохранен в {filename}")
    except IOError as e:
        tqdm.write(f"Ошибка при сохранении отчета: {e}")

def parse_range(range_string):
    try:
        start_ip, end_ip = range_string.split('-')
        start_ip = ipaddress.ip_address(start_ip)
        end_ip = ipaddress.ip_address(end_ip)
        return [str(ip) for ip in ipaddress.summarize_address_range(start_ip, end_ip)]
    except ValueError as e:
        tqdm.write(f"Неверный формат диапазона: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(description="Пингование IP-адресов из CIDR или диапазона.")
    parser.add_argument("target", help="CIDR диапазон, диапазон IP через '-' или домен для пингования.")
    parser.add_argument("-a", "--show-all", action="store_true", help="Показывать все IP-адреса, а не только работающие.")
    parser.add_argument("-s", "--save-report", help="Сохранить отчет в указанный файл.")
    parser.add_argument("-f", "--format", choices=["txt"], default="txt", help="Формат отчета (только txt).")
    parser.add_argument("-t", "--timeout", type=int, default=1, help="Время ожидания для пинга в секундах.")
    parser.add_argument("-m", "--max-threads", type=int, default=10, help="Максимальное количество потоков.")
    parser.add_argument("-p", "--check-ports", type=str, help="Проверить открытые порты (укажите через запятую или диапазон через -).")
    parser.add_argument("--traceroute", action="store_true", help="Включить проверку traceroute для работающих IP.")

    args = parser.parse_args()

    if '-' in args.target:
        ip_list = parse_range(args.target)
        if not ip_list:
            return
    elif '/' in args.target:
        ip_list = [str(ip) for ip in ipaddress.ip_network(args.target, strict=False).hosts()]
    else:
        cidr = resolve_domain_to_cidr(args.target)
        if not cidr:
            return
        ip_list = [str(ip) for ip in ipaddress.ip_network(cidr, strict=False).hosts()]

    check_ports = parse_ports(args.check_ports) if args.check_ports else None

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.max_threads) as executor:
        future_to_ip = {executor.submit(ping_host, ip, args.timeout): ip for ip in ip_list}
        with tqdm(total=len(future_to_ip), desc="Scanning", unit="ip", position=0, leave=False) as pbar:
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                is_alive = future.result()
                results[ip] = {"alive": is_alive}
                if check_ports and is_alive:
                    results[ip]["open_ports"] = []
                    for port in check_ports:
                        if check_port(ip, port, args.timeout):
                            results[ip]["open_ports"].append(port)
                if args.show_all or is_alive:
                    status = "работает" if is_alive else "не работает"
                    ports_info = f", открытые порты: {results[ip].get('open_ports', [])}" if is_alive else ""
                    tqdm.write(f"{ip} {status}{ports_info}")

                if is_alive and args.traceroute:
                    traceroute_output = traceroute(ip)
                    if traceroute_output:
                        tqdm.write(f"Traceroute для {ip}:\n{traceroute_output}")
                        results[ip]["traceroute"] = traceroute_output

                pbar.update(1)

    if args.save_report:
        save_report(results, args.save_report, args.format)

if __name__ == "__main__":
    art = r"""
___________                             .__                 ___.            __          .__  .__  .__  ________  ____ 
\_   _____/____  ___________.__. ______ |__| ____    ____   \_ |__ ___.__. |  | __ ____ |  | |  | |  | \_____  \/_   |
 |    __)_\__  \ \___   <   |  | \____ \|  |/    \  / ___\   | __ <   |  | |  |/ // __ \|  | |  | |  |   _(__  < |   |
 |        \/ __ \_/    / \___  | |  |_> >  |   |  \/ /_/  >  | \_\ \___  | |    <\  ___/|  |_|  |_|  |__/       \|   |
/_______  (____  /_____ \/ ____| |   __/|__|___|  /\___  /   |___  / ____| |__|_ \\___  >____/____/____/______  /|___|
        \/     \/      \/\/      |__|           \//_____/        \/\/           \/    \/                      \/      
    """
    print(art)           
    main()