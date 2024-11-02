# easyping
Mass ip ping scanner

requirements:
$ pip install ipaddress subprocess concurrent.futures socket argparse tqdm

Usage:

$ python3 eazyping.py -h

eazyping.py [-h] [-a] [-s SAVE_REPORT] [-f {txt}] [-t TIMEOUT] [-m MAX_THREADS] [-p CHECK_PORTS] [--traceroute] target

Пингование IP-адресов из CIDR.



positional arguments:

  target                CIDR диапазон или домен для пингования.
	
options:

  -h, --help            show this help message and exit 
  
  -a, --show-all        Показывать все IP-адреса, а не только работающие.
  
  -s SAVE_REPORT, --save-report SAVE_REPORT  Сохранить отчет в указанный файл.
  
  -f {txt}, --format {txt}  Формат отчета (только txt).
  
  -t TIMEOUT, --timeout TIMEOUT  Время ожидания для пинга в секундах.
  
  -m MAX_THREADS, --max-threads MAX_THREADS Максимальное количество потоков.
  
  -p CHECK_PORTS, --check-ports CHECK_PORTS  Проверить открытые порты (укажите через запятую или диапазон через -).
  
  --traceroute  Включить проверку traceroute для работающих IP.
