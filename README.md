
[traceroute]: https://github.com/Kelll31/eazyping/blob/main/img/example%20--traceroute.png?raw=true "Traceroute example"
[example]: https://github.com/user-attachments/assets/40429bfd-9cb7-48bb-8327-b84ebc18e45b "Usage example"

# easyping
Mass ip ping scanner

### requirements:
```console
$ pip install ipaddress subprocess concurrent.futures socket argparse tqdm
```

### Usage:
![example]
```console
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
```

### Traceroute:
![traceroute]
